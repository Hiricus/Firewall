import mysql.connector as con

class MySQL:
    def __init__(self, host, port, user, passwd, database_name):
        self.connection = con.connect(
            host=host,
            port=port,
            user=user,
            passwd=passwd,
            database=database_name
        )

    def __del__(self):
        self.connection.close()

    # Информация о таблице, добавил чисто на всякий
    def table_info(self, table_name):
        cursor = self.connection.cursor()
        cursor.execute(f"DESCRIBE `{table_name}`")
        columns = cursor.fetchall()
        cursor.close()

        return columns

    # Во время исполнения порядковые номера совпадут поэтому возможно стоит переделать.
    # Зато работает в сейф моде
    def swap_rule_order(self, n1, n2):
        swap_query = [f"SET @num1 := {n1};",
                      f"SET @num2 := {n2};",
                      "SET @id1 := (SELECT rule_id FROM `rules` WHERE rule_order = @num1);",
                      "SET @id2 := (SELECT rule_id FROM `rules` WHERE rule_order = @num2);",
                      "UPDATE `rules` SET rule_order = @num2 WHERE rule_id = @id1;",
                      "UPDATE `rules` SET rule_order = @num1 WHERE rule_id = @id2;"]
        cursor = self.connection.cursor()
        for query in swap_query:
            cursor.execute(query)
            cursor.fetchall()
        self.connection.commit()
        cursor.close()

    def change_rule_order(self, from_num, to_num):
        change_query = [f"SET @num1 := {from_num};",
                        f"SET @num2 := {to_num};",
                        "SET @id := (SELECT rule_id FROM `rules` WHERE rule_order = @num1);",
                        "UPDATE `rules` SET rule_order = @num2 WHERE rule_id = @id;"]
        cursor = self.connection.cursor()
        for query in change_query:
            cursor.execute(query)
            cursor.fetchall()
        self.connection.commit()
        cursor.close()

    # Добавляет правило на определённое место
    def add_rule(self, order, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation=''):
        insert_query = (f"INSERT INTO `rules` (rule_order, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation)"
                        f"VALUES ({order}, '{direction}', '{protocol}', '{src_ips}', '{dst_ips}', '{src_ports}', '{dst_ports}', '{result}', '{annotation}')")
        cursor = self.connection.cursor()
        cursor.execute(insert_query)
        self.connection.commit()
        cursor.close()

    # Вставляет правило на указанную позицию
    def insert_rule(self, position, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation=''):
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM `rules`")
        last_rule_num = cursor.fetchall()[0][0] - 1
        cursor.close()

        # Если таблица пуста - добавляем правило на нулевую позицию
        if last_rule_num < 0:
            self.add_rule(0, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation)
        else:
            while last_rule_num >= position:
                self.change_rule_order(last_rule_num, last_rule_num + 1)
                last_rule_num -= 1
            self.add_rule(position, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation)

    # Вставляет правило в конец
    def append_rule(self, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation=''):
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM `rules`")
        order = cursor.fetchall()[0][0]
        cursor.close()

        self.add_rule(order, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation)

    # Удаляет правило по порядковому номеру
    def del_rule_by_order(self, order):
        delete_query = f"DELETE FROM `rules` WHERE rule_order = {order}"
        cursor = self.connection.cursor()
        cursor.execute(delete_query)
        self.connection.commit()
        cursor.close()

    def del_rule_by_value(self, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result):
        delete_query = (f"DELETE FROM `rules` "
                        f"WHERE direction = '{direction}' "
                        f"AND protocol = '{protocol}' "
                        f"AND src_ips = '{src_ips}' "
                        f"AND dst_ips = '{dst_ips}' "
                        f"AND src_ports = '{src_ports}' "
                        f"AND dst_ports = '{dst_ports}' "
                        f"AND result = '{result}'")  # ну и какого хрена оно в скобках? Перепроверить работоспособность
        cursor = self.connection.cursor()
        cursor.execute(delete_query)
        self.connection.commit()
        cursor.close()

    # Удаляет правило с указанной позиции
    def rule_pop(self, position):
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM `rules`")
        last_rule_num = cursor.fetchall()[0][0]
        cursor.close()

        self.del_rule_by_order(position)
        while position < last_rule_num:
            self.change_rule_order(position + 1, position)
            position += 1

    # Возвращает логическое значение и порядковый номер правила (-1 если его нет)
    def is_exists(self, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result):
        cursor = self.connection.cursor()
        exists_query = (f"SELECT * FROM `rules` "
                        f"WHERE direction = '{direction}' "
                        f"AND protocol = '{protocol}' "
                        f"AND src_ips = '{src_ips}' "
                        f"AND dst_ips = '{dst_ips}' "
                        f"AND src_ports = '{src_ports}' "
                        f"AND dst_ports = '{dst_ports}' "
                        f"AND result = '{result}'")
        cursor.execute(exists_query)
        found_rule = cursor.fetchall()
        cursor.close()

        if found_rule == []:
            return (False, -1)
        else:
            return (True, found_rule[0][1])

    # Возвращает все правила без их id
    def get_all_rules(self):
        get_all_query = "SELECT * FROM `rules` ORDER BY rule_order ASC"
        cursor = self.connection.cursor()
        cursor.execute(get_all_query)
        all_rules = cursor.fetchall()
        cursor.close()

        for i in range(len(all_rules)):
            all_rules[i] = list(all_rules[i])
            all_rules[i].pop(0)

        return all_rules




dbcon = MySQL(
    host="127.0.0.1",
    port="3306",
    user="root",
    passwd="2556145",
    database_name="firewalldb"
)

# s = dbcon.is_exists('0', 'ICMP', '', '', '', '53-53', 'allow')

rules = dbcon.get_all_rules()
for rule in rules:
    print(rule)