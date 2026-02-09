# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (JSplitPane, JScrollPane, JTable, JButton, JPanel, 
    JTextField, JLabel, JMenuItem, SwingUtilities, JProgressBar, JFileChooser)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Color, BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.util import ArrayList
from java.lang import Object
from threading import Thread
import time

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpFuzzer")
        
        self.source_msg = None
        self.is_active = False
        self.payloads = ["admin", "login", "api", "dev", "test", "backup", "config", ".env"]
        
        self.results_table_model = DefaultTableModel(["Path", "Status", "Length", "Time (ms)"], 0)
        self.display_table = JTable(self.results_table_model)
        self.display_table.setDefaultRenderer(Object, CustomStatusRenderer())
        
        self.starter = JButton("Start")
        self.stopper = JButton("Stop")
        self.cleaner = JButton("Clear")
        self.loader = JButton("Load Wordlist")
        
        self.starter.addActionListener(GenericClickProcessor(self.initiate_fuzzing))
        self.stopper.addActionListener(GenericClickProcessor(self.halt_fuzzing))
        self.cleaner.addActionListener(GenericClickProcessor(self.reset_results))
        self.loader.addActionListener(GenericClickProcessor(self.import_wordlist))
        
        self.status_text = JLabel("Ready")
        self.progress_indicator = JProgressBar(0, 100)
        
        navigation = JPanel(FlowLayout(FlowLayout.LEFT))
        navigation.add(self.starter)
        navigation.add(self.stopper)
        navigation.add(self.cleaner)
        navigation.add(self.loader)
        navigation.add(self.status_text)
        navigation.add(self.progress_indicator)
        
        self.layout_container = JPanel(BorderLayout())
        self.layout_container.add(navigation, BorderLayout.NORTH)
        self.layout_container.add(JScrollPane(self.display_table), BorderLayout.CENTER)
        
        callbacks.customizeUiComponent(self.layout_container)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def getTabCaption(self): return "BurpFuzzer"
    def getUiComponent(self): return self.layout_container

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to BurpFuzzer", actionPerformed=lambda x: self.transfer_request(invocation)))
        return menu_list

    def transfer_request(self, context):
        selection = context.getSelectedMessages()
        if selection:
            self.source_msg = selection[0]
            target_info = self.helpers.analyzeRequest(self.source_msg)
            self.status_text.setText("Target: " + str(target_info.getUrl()))

    def import_wordlist(self, event):
        picker = JFileChooser()
        if picker.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            selected_file = picker.getSelectedFile()
            raw_content = open(selected_file.absolutePath, 'r').read()
            self.payloads = filter(None, raw_content.splitlines())
            self.status_text.setText("Words: " + str(len(self.payloads)))

    def initiate_fuzzing(self, event):
        if self.source_msg and not self.is_active:
            self.is_active = True
            self.status_text.setText("Scanning...")
            worker = Thread(target=self.execute_scan)
            worker.daemon = True
            worker.start()

    def halt_fuzzing(self, event): 
        self.is_active = False
        self.status_text.setText("Interrupted")

    def reset_results(self, event): 
        self.results_table_model.setRowCount(0)
        self.progress_indicator.setValue(0)

    def execute_scan(self):
        parsed_req = self.helpers.analyzeRequest(self.source_msg)
        connection = self.source_msg.getHttpService()
        
        uri_path = parsed_req.getUrl().getPath()
        directory_prefix = uri_path if uri_path.endswith('/') else (uri_path + '/')
        
        total_count = float(len(self.payloads))
        current_index = 0
        
        for item in self.payloads:
            if not self.is_active: break
            
            target_path = directory_prefix + item.lstrip('/')
            header_list = list(parsed_req.getHeaders())
            header_list[0] = header_list[0].replace(uri_path, target_path)
            
            final_request = self.helpers.buildHttpMessage(header_list, None)
            
            clock_start = time.time()
            outcome = self.callbacks.makeHttpRequest(connection, final_request)
            duration = int((time.time() - clock_start) * 1000)
            
            if outcome:
                res_data = self.helpers.analyzeResponse(outcome.getResponse())
                http_status = res_data.getStatusCode()
                full_raw = outcome.getResponse()
                body_len = len(full_raw) - res_data.getBodyOffset()
                
                def update_ui():
                    self.results_table_model.addRow([item, http_status, body_len, duration])
                SwingUtilities.invokeLater(update_ui)
            
            current_index += 1
            def update_progress():
                self.progress_indicator.setValue(int((current_index / total_count) * 100))
            SwingUtilities.invokeLater(update_progress)
            
        self.is_active = False
        def finalize():
            self.status_text.setText("Task Finished")
        SwingUtilities.invokeLater(finalize)

class GenericClickProcessor(ActionListener):
    def __init__(self, action_func):
        self.action_func = action_func
    def actionPerformed(self, event):
        self.action_func(event)

class CustomStatusRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, selected, focused, row, col):
        component = super(CustomStatusRenderer, self).getTableCellRendererComponent(table, value, selected, focused, row, col)
        
        if not selected:
            code_value = table.getValueAt(row, 1)
            
            if code_value in [200, 204]:
                component.setBackground(Color(0xCBFFD3))
            elif code_value in [301, 302, 401, 403]:
                component.setBackground(Color(0xFFFDCB))
            elif code_value == 404:
                component.setBackground(Color(0xFFCBCE))
            else:
                component.setBackground(Color.WHITE)
        
        return component