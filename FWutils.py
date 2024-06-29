# Для соответствия номеров протоколов их названиям

protocols = {
    0: 'HOPOPT',
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6'
}

def compareIpAddr(ip1, ip2):
    # Разделяем IP-адреса на октеты
    octets1 = list(map(int, ip1.split('.')))
    octets2 = list(map(int, ip2.split('.')))

    # Сравниваем октеты
    for o1, o2 in zip(octets1, octets2):
        if o1 < o2:
            return 1
        elif o1 > o2:
            return -1

    # Если все октеты равны
    return 0

def simplify_range(data):
    if data == '':
        pass
    elif len(data.split('-')) == 1:
        data = data + '-' + data
    return data