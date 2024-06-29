import time
import threading
import fw_core

# def second_thr():
#     while True:
#         print(f"Привет из второго потока, вот данные: Bardoon")
#         time.sleep(5)
#
#
# thr = threading.Thread(target=second_thr, name="alter-thr", daemon=True)
# thr.start()
# time.sleep(2)
#
# print("finish")
# while True:
#     print("Привет из первого потока")
#     time.sleep(2.5)

# fwc = fw_core.FirewallCore()
# fwc.sendIPv6(True)

def fwc_daemon_start(firewallCore):
    fwc_thread = threading.Thread(target=firewallCore.start, daemon=True, name='fwc_thread')
    fwc_thread.start()


# fwc_daemon_start(firewallCore=fwc)
#
# while True:
#     time.sleep(1)
#     print("Greetings from the main thread!!!")