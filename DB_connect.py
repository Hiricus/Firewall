import mysql.connector as con

# connection = con.connect(
#     host="127.0.0.1",
#     port="3306",
#     user="root",
#     passwd="2556145",
#     database="firewalldb"
# )
# mycursor = connection.cursor()
#
# mycursor.execute("SELECT COUNT(*) FROM `rules`")
# print(mycursor.fetchall()[0][0])


class MySQL:
    def __init__(self, host, port, user, passwd, database_name):
        self.connection = con.connect(
            host=host,
            port=port,
            user=user,
            passwd=passwd,
            database=database_name
        )

    # Информация о таблице, добавил чисто на всякий
    def table_info(self, table_name):
        cursor = self.connection.cursor()
        cursor.execute(f"DESCRIBE `{table_name}`")
        columns = cursor.fetchall()
        cursor.close()

        return columns

    def add_rule(self, order, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation=''):
        insert_query = (f"INSERT INTO `rules` (rule_order, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation)"
                        f"VALUES ('{order}', '{direction}', '{protocol}', '{src_ips}', '{dst_ips}', '{src_ports}', '{dst_ports}', '{result}', '{annotation}')")
        cursor = self.connection.cursor()
        cursor.execute(insert_query)
        self.connection.commit()
        cursor.close()

    # Вставляет правило в конец
    def append_rule(self, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation=''):
        with self._cursor as cursor:
            cursor.execute("SELECT COUNT(*) FROM `rules`")
            order = cursor.fetchall()[0][0]

        self.add_rule(order, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result, annotation)

    # Возможно стоит поменять id на order
    def del_rule_by_id(self, id):
        delete_query = f"DELETE FROM `rules` WHERE rule_id = {id}"
        with self._cursor as cursor:
            cursor.execute(delete_query)
            self.connection.commit()

    def del_rule_by_value(self, direction, protocol, src_ips, dst_ips, src_ports, dst_ports, result):
        delete_query = (f"DELETE FROM `rules` "
                        f"WHERE direction = '{direction}' "
                        f"AND protocol = '{protocol}' "
                        f"AND src_ips = '{src_ips}' "
                        f"AND dst_ips = '{dst_ips}' "
                        f"AND src_ports = '{src_ports}' "
                        f"AND dst_ports = '{dst_ports}' "
                        f"AND result = '{result}'")
        with self._cursor as cursor:
            cursor.execute(delete_query)
            self.connection.commit()

    # def is_exists(self):





dbcon = MySQL(
    host="127.0.0.1",
    port="3306",
    user="root",
    passwd="2556145",
    database_name="firewalldb"
)

# s = dbcon.table_info("rules")

# dbcon.append_rule('', '', '87.236.19.243-87.236.19.243', '', '', '', '', 'Блокируем Первомайск онлайн')
# dbcon.append_rule('', '', '87.236.19.243-87.236.19.243', '', '', '', '', 'Блокируем Первомайск')
dbcon.add_rule('1', '', '', '87.236.19.243-87.236.19.243', '', '', '', '', 'Блокируем Первомайск')
dbcon.add_rule('1', '', '', '87.236.19.243-87.236.19.243', '', '', '', '', 'Блокируем Первомайск онлайн')
