import threading
from time import sleep


event = None
started = False

#TODO: SEPARATE THREADS BY CRITICAL SECTION

def refresh(latest_event, wait_for, *args, **kwargs):
    global event
    t = threading.Thread(target=__wait__, args=(wait_for, *args), kwargs=kwargs)
    t.start()
    event = latest_event

def __wait__(t, *args, **kwargs):
    global started
    if started: return
    started = True
    sleep(t)
    __run__(*args, **kwargs)
    started = False

def __run__(*args, **kwargs):
    global event
    if not event: return
    event(*args, **kwargs)
    event = None
