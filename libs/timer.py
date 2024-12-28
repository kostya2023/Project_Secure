import sys
sys.path.append(".")
from libs import db
import time
import threading
db_path = "storage/db.db"

def banned(time_ : int, IP: str):
    print(f"Starting timed ban with args time: {time_}, IP: {IP}")
    time.sleep(time_)
    db.execute_SQL(db_path, "UPDATE Data SET time_banned = ? WHERE IP = ?", ("NULL", IP,))
    db.execute_SQL(db_path, "UPDATE Data SET banned = ? WHERE IP = ?", ("False", IP,))
    print(f"Timer ban finished for IP: {IP}")


def logined(time_ : int, IP: str):
    print(f"Starting timed login with args time: {time_}, IP: {IP}")
    time.sleep(time_)
    db.execute_SQL(db_path, "UPDATE Data SET time_logined = ? WHERE IP = ?", ("NULL", IP,))
    db.execute_SQL(db_path, "UPDATE Data SET logined = ? WHERE IP = ?", ("False", IP,))
    print(f"Timer login finished for IP: {IP}")

def cookie(IP : str, time_ : int):
    print(f"Starting timed cookie with args time: {time_}, IP: {IP}")
    time.sleep(time_)
    db.execute_SQL(db_path, "DELETE FROM Cookie WHERE own_ip = ?", (IP,))
    print(f"Timer cookie finished for IP: {IP}")

def start_timer(choice : str, IP : str, time : int):
    if choice == "logined":
        logined_thread = threading.Thread(target=logined, args=(time, IP), daemon=True)
        logined_thread.start()
    elif choice == "banned":
        banned_thread = threading.Thread(target=banned, args=(time, IP), daemon=True)
        banned_thread.start()
    elif choice == "cookie":
        cookie_thread = threading.Thread(target=cookie, args=(IP, time), daemon=True)
        cookie_thread.start()
    else:
        raise Exception("Error, uncorrect choice.")

    