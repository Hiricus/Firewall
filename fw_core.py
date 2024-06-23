import pydivert
import FWutils

class FirewallCore:
    __instance = None
    __w = None

    # проверка на соответствие одного параметра из правила
    def checkRule(self, param, packet, rule_value):
        if param == 'direction':
            check_value = str(int(packet.direction))  # напрямую в строку лучше не переводить, через инт норм
        elif param == 'protocol':
            check_value = str(FWutils.protocols[packet.protocol[0]])
        else:
            raise ValueError(f'Invalid ip packet parameter: {param}')

        if rule_value == 'None':
            pass
        elif rule_value == check_value:
            pass
        else:
            self.__is_fit_F = False

    # проверка на соответствие порта диапазону портов
    # Работает тупо т.к. криво учитывает отсутствие порта
    def checkRangedRule_port(self, param, packet, rule_values):
        if param == 'src_port_range':
            check_value = str(packet.src_port)
        elif param == 'dst_port_range':
            check_value = str(packet.dst_port)
        else:
            raise ValueError(f'Invalid ip packet parameter: {param}')

        rule_values = rule_values.split('-')

        # На случай если порта нет
        if check_value == 'None':
            check_value = -1

        if rule_values[0] == 'None':
            pass
        elif (int(rule_values[0]) <= int(check_value)) and (int(check_value) <= int(rule_values[1])):
            pass
        else:
            self.__is_fit_F = False


    # проверка на соответствие адреса диапазону адресов
    def checkRangedRule_addr(self, param, packet, rule_values):
        if param == 'src_ip_range':
            check_value = str(packet.src_addr)
        elif param == 'dst_ip_range':
            check_value = str(packet.dst_addr)
        else:
            raise ValueError(f'Invalid ip packet parameter: {param}')

        rule_values = rule_values.split('-')
        if rule_values[0] == 'None':
            pass
        elif (FWutils.compareIpAddr(rule_values[0], check_value) in (0, 1)) and (FWutils.compareIpAddr(check_value, rule_values[1]) in (0, 1)):
            pass
        else:
            self.__is_fit_F = False

    # Типа синглтон
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
        self.__is_ipv6 = True


    def start(self):
        # открываем хэндлер pydivert
        self.__w.open()
        print("Начало прослушивания...")

        # Чтение правил
        with open("ruleset.txt", "r") as rulefile:
            self.rules = rulefile.readlines()
        self.rules = self.rules[1:]  # Убирает референсную строчку

        # превращаем строку в список правил
        for i in range(len(self.rules)):
            self.rules[i] = self.rules[i].strip('\n')
            self.rules[i] = self.rules[i].split(';')
        # print(self.rules)

        # цикл работающий с пакетом
        for packet in self.__w:
            # print(FWutils.protocols[packet.protocol[0]])
            # print()

            # Не работает с ipv6
            if packet.ipv6:
                if self.__is_ipv6:
                    self.__w.send(packet)
                else:
                    pass
                continue

            # цикл работающий с одним правилом
            for self.single_rule in self.rules:
                self.__is_fit_F = True

                # проверки пакета
                # i/o и протокол
                self.checkRule('direction', packet, self.single_rule[1])
                self.checkRule('protocol', packet, self.single_rule[2])

                # адреса
                self.checkRangedRule_addr('src_ip_range', packet, self.single_rule[3])
                self.checkRangedRule_addr('dst_ip_range', packet, self.single_rule[4])

                # порты
                self.checkRangedRule_port('src_port_range', packet, self.single_rule[5])
                self.checkRangedRule_port('dst_port_range', packet, self.single_rule[6])

                # действие, если пакет подошёл под правило
                if self.__is_fit_F:
                    if self.single_rule[7] == 'allow':
                        self.__w.send(packet)
                    elif self.single_rule[7] == 'reject':
                        print(f'Rejected packet from ip {packet.src_addr}, on ports {packet.src_port}:{packet.dst_port}, protocol {FWutils.protocols[packet.protocol[0]]} using rule {self.single_rule[0]}     {str(packet.direction)}')
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

    # Поведение с пакетами ipv6
    def sendIPv6(self, is_send):
        self.__is_ipv6 = is_send

    def isIPv6Sent(self):
        return self.__is_ipv6



fwc = FirewallCore()
fwc.sendIPv6(True)

fwc.start()