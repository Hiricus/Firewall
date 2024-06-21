import pydivert
import FWutils

class FirewallCore:
    __instance = None
    __w = None

    # проверка на соответствие одного параметра из правила
    def checkRule(self, param, packet, rule_value):
        if param == 'direction':
            check_value = str(packet.direction)
        elif param == 'protocol':
            check_value = str(FWutils.protocols[packet.protocol[0]])
        elif param == 'src_port':
            check_value = str(packet.src_port)
        elif param == 'dst_port':
            check_value = str(packet.dst_port)
        elif param == 'src_ip':
            check_value = str(packet.src_addr)
        elif param == 'dst_ip':
            check_value = str(packet.dst_addr)

        if rule_value == 'None':
            self.__is_fit_F = self.__is_fit_F
        elif rule_value == check_value:
            self.__is_fit_F = self.__is_fit_F
        else:
            self.__is_fit_F = False

    # проверка на соответствие порта диапазону портов
    def checkRangedRule_port(self, param, packet, rule_values):
        if param == 'src_port_range':
            check_value = str(packet.src_port)
        elif param == 'dst_port_range':
            check_value = str(packet.dst_port)

        rule_values = rule_values.split('-')
        if check_value == 'None':
            self.__is_fit_F = False
        elif (rule_values[0] == 'None'):
            self.__is_fit_F = self.__is_fit_F
        elif (int(rule_values[0]) <= int(check_value)) and (int(check_value) <= int(rule_values[1])):
            self.__is_fit_F = self.__is_fit_F
        else:
            self.__is_fit_F = False

    # проверка на соответствие адреса диапазону адресов
    def checkRangedRule_addr(self, param, packet, rule_values):
        if param == 'src_ip_range':
            check_value = str(packet.src_addr)
        elif param == 'dst_ip_range':
            check_value = str(packet.dst_addr)

        rule_values = rule_values.split('-')
        if rule_values[0] == 'None':
            self.__is_fit_F = self.__is_fit_F
        elif (FWutils.compareIpAddr(rule_values[0], check_value) in (0, 1)) and (FWutils.compareIpAddr(check_value, rule_values[1]) in (0, 1)):
            self.__is_fit_F = self.__is_fit_F
        else:
            self.__is_fit_F = False

    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

    def __del__(self):
        # self.__w.close()
        FirewallCore.__instance = None

    def __init__(self):
        # создаём хэндлер pydivert
        self.__w = pydivert.WinDivert()


    def start(self):
        # открываем хэндлер pydivert
        self.__w.open()
        print("Начало прослушивания...")

        # Чтение правил
        with open("ruleset.txt", "r") as rulefile:
            self.rules = rulefile.readlines()
        self.rules = self.rules[1:]  # Убирает референсную строчку

        # цикл работающий с пакетом
        for packet in self.__w:
            # print(FWutils.protocols[packet.protocol[0]])
            # print()

            # Не работает с ipv6
            if packet.ipv6:
                self.__w.send(packet)
                continue
            # цикл работающий с одним правилом
            for self.single_rule in self.rules:
                self.__is_fit_F = True

                # превращаем строку в список правил
                self.single_rule = self.single_rule.strip('\n')
                self.single_rule = self.single_rule.split(';')
                # print(self.single_rule)

                # проверки пакета
                # i/o и протокол
                self.checkRule('direction', packet, self.single_rule[1])
                self.checkRule('protocol', packet, self.single_rule[2])

                # порты
                self.checkRule('src_port', packet, self.single_rule[3])
                self.checkRangedRule_port('src_port_range', packet, self.single_rule[4])
                self.checkRule('dst_port', packet, self.single_rule[5])
                self.checkRangedRule_port('dst_port_range', packet, self.single_rule[6])

                # адреса
                self.checkRule('src_ip', packet, self.single_rule[7])
                self.checkRangedRule_addr('src_ip_range', packet, self.single_rule[8])
                self.checkRule('dst_ip', packet, self.single_rule[9])
                self.checkRangedRule_addr('dst_ip_range', packet, self.single_rule[10])

                # действие, если пакет подошёл под правило
                if self.__is_fit_F:
                    if self.single_rule[11] == 'allow':
                        self.__w.send(packet)
                    elif self.single_rule[11] == 'reject':
                        print(f'Rejected packet from ip {packet.src_addr}, on port {packet.dst_port}, protocol {FWutils.protocols[packet.protocol[0]]} using rule {self.single_rule[0]}')
                        # print(self.single_rule)
                        print()
                        pass
                    else:
                        pass
                    break
            pass

    def stop(self):
        # закрываем хэндлер
        self.__w.close()
        print("Остановка прослушивания...")





fwc = FirewallCore()
fwc.start()