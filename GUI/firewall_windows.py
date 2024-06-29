import sys
import threading

from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QLabel
from PyQt5.QtCore import pyqtSlot
import time

import DB_connect
import fw_core
import FWutils

class DelRuleWindow(QDialog):
    def __init__(self):
        super().__init__()

        # Set window properties
        loadUi('deleting_window.ui', self)
        # self.lineEdit_annotation.setWordWrap(True)

        self.delRuleBtn.clicked.connect(self.delete_rule)

        # Create layout for the popup window
        layout = QVBoxLayout()

        # Set the layout for the popup window
        self.setLayout(layout)

    def delete_rule(self):
        order = self.lineEditDel_order.text()

        try:
            order = int(order)
        except:
            print('Incorrect input in field: order')
            return

        dbcon = DB_connect.MySQL(
            host="127.0.0.1",
            port="3306",
            user="root",
            passwd="2556145",
            database_name="firewalldb"
        )

        is_exists = dbcon.is_exists_on_order(order)

        if is_exists:
            dbcon.rule_pop(order)
            print("Сносим нафиг")
        else:
            print("А что удалять то?")

        dbcon.close_connection()



class AddRuleWindow(QDialog):
    def __init__(self):
        super().__init__()

        # Set window properties
        loadUi('adding_window.ui', self)
        # self.lineEdit_annotation.setWordWrap(True)

        self.addRuleBtn.clicked.connect(self.add_rule)

        # Create layout for the popup window
        layout = QVBoxLayout()

        # Set the layout for the popup window
        self.setLayout(layout)

    def add_rule(self):
        order = self.lineEdit_order.text()
        direction = self.lineEdit_direction.text()
        protocol = self.lineEdit_protocol.text()

        src_ip = FWutils.simplify_range(self.lineEdit_src_ips.text())
        dst_ip = FWutils.simplify_range(self.lineEdit_dst_ips.text())
        src_port = FWutils.simplify_range(self.lineEdit_src_ports.text())
        dst_port = FWutils.simplify_range(self.lineEdit_dst_ports.text())

        result = self.lineEdit_result.text()
        annotation = self.lineEdit_annotation.text()

        # Проверка ввода на соответствие условиям (ну чисто чтобы бд не ломало)
        try:
            order = int(order)
        except:
            print('Incorrect input in field: order')
            return

        if result not in ('allow', 'reject'):
            print('Incorrect input in field: result')
            return


        print([order, direction, protocol, src_ip, dst_ip, src_port, dst_port, result, annotation])

        # Проверка на уникальность и добавление правила
        dbcon = DB_connect.MySQL(
            host="127.0.0.1",
            port="3306",
            user="root",
            passwd="2556145",
            database_name="firewalldb"
        )

        is_unique = not dbcon.is_exists(direction, protocol, src_ip, dst_ip, src_port, dst_port, result)[0]

        if is_unique:
            dbcon.insert_rule(order, direction, protocol, src_ip, dst_ip, src_port, dst_port, result, annotation)
            print('Зашибись, добавляем')
        else:
            print('Было уже')

        dbcon.close_connection()



class ExampleApp(QMainWindow):
    def __init__(self):
        super(ExampleApp, self).__init__()

        loadUi('main_window.ui', self)

        # Задаём инфу по таблицам
        self.tableWidget.setColumnWidth(0, 50)
        self.tableWidget.setColumnWidth(1, 70)
        self.tableWidget.setColumnWidth(2, 100)
        self.tableWidget.setColumnWidth(3, 150)
        self.tableWidget.setColumnWidth(4, 150)
        self.tableWidget.setColumnWidth(5, 110)
        self.tableWidget.setColumnWidth(6, 110)
        self.tableWidget.setColumnWidth(7, 70)
        self.tableWidget.setColumnWidth(8, 188)

        self.tableWidget.setHorizontalHeaderLabels(["№", "direction", "protocol", "src_ips", "dst_ips", "src_ports", "dst_ports", "result", "annotation"])

        # Задаём инфу по кнопкам
        self.reloadRulesBtn.clicked.connect(self.loaddata)
        self.startFwcBtn.clicked.connect(self.firewall_start)
        self.addRuleBtn.clicked.connect(self.show_adding_window)
        self.deleteRuleBtn.clicked.connect(self.show_deleting_window)


    def loaddata(self):
        dbcon = DB_connect.MySQL(
            host="127.0.0.1",
            port="3306",
            user="root",
            passwd="2556145",
            database_name="firewalldb"
        )

        rules = dbcon.get_all_rules()
        dbcon.close_connection()

        self.tableWidget.setRowCount(len(rules))

        for i in range(len(rules)):
            for j in range(len(rules[0])):
                self.tableWidget.setItem(i, j, QTableWidgetItem(str(rules[i][j])))

        print('Refreshed!')

    def firewall_start(self):
        self.startFwcBtn.setStyleSheet("QPushButton"
                                       "{"
                                       "background-color: rgba(0, 255, 0, 128);"
                                       "color: white;"
                                       "font-size: 16px;"
                                       "border-radius: 50%;"
                                       "}")
        fwc = fw_core.FirewallCore()
        fwc.sendIPv6(True)

        fwc_thr = threading.Thread(target=fwc.start, daemon=True)
        fwc_thr.start()

        self.startFwcBtn.setEnabled(False)

    def show_adding_window(self):
        popup = AddRuleWindow()
        popup.exec_()

    def show_deleting_window(self):
        popup = DelRuleWindow()
        popup.exec_()



app = QApplication(sys.argv)
UIWindow = ExampleApp()
UIWindow.loaddata()
UIWindow.show()


app.exec_()