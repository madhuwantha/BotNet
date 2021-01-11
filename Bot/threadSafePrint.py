import threading

lock = threading.Lock()


def threadSafePrint(*args, **kwargs):
    with lock:
        print(*args, **kwargs)
