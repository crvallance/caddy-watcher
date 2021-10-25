import configparser
import requests
import json
import base64
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


config = configparser.ConfigParser()
config.sections()
config.read('config.ini')


def notify(username, config):
    myurl = config['apihook']['hook_url'] + ':' + config['apihook']['hook_port'] + \
        '/api/webhook/' + config['apihook']['hook_id'] + f'?username={username}'
    my_json = {'hook': config['apihook']['hook_key']}
    r = requests.post(url=myurl, json=my_json)
    r.raise_for_status()


def parse_log(logfile):
    with open(logfile, 'r') as log:
        lines = log.readlines()
        last = lines[-1]
        data = json.loads(last)
        try:
            user_data = data['request']['headers']['Authorization']
            user_base64 = user_data[0].split(' ')[1]
            user_string = base64.b64decode(user_base64).decode('ascii')
            username = user_string.split(':')[0]
            return(username)
        except KeyError:
            return('FAIL MESSAGE: KeyError')


def on_modified(event):
    username = parse_log(event.src_path)
    notify(username, config)


def main():
    logfile = config['logwatch']['log_path']
    patterns = ['*']
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True
    my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    my_event_handler.on_modified = on_modified
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, logfile, recursive=go_recursively)
    my_observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()


if __name__ == "__main__":
    main()
