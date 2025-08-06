import pathlib
import socket
import pywinauto
from time import sleep

max_connection_retries = 5
root_dir_path = 'C:\\Users\\admin\\wireguard-tools\\'
anmezia_wg_path = 'C:\\Program Files\\AmneziaWG\\amneziawg.exe'
connection_check_host = '74.208.159.18'

    
def create_config(template : list[str], filenum : int):
    with open(f'WARP{filenum}.conf', 'w') as f:
        f.writelines(template)
        
    if filenum > 1:
        pathlib.Path(f'WARP{filenum - 1}.conf').unlink()
    return


if __name__ == '__main__':
    with open('WARP.conf') as config:
        config_template = config.readlines()

    endpoint_wrapper = lambda s: f'Endpoint = {s}\n'
    socket.setdefaulttimeout(2)
        
    # ips = open('cf_ips_v4.txt')
    # networks = list(map(lambda x: ip_network(x.replace('\n', ''), True), ips))
    # ips.close()
    cf_ports = [2408, 500, 1701, 4500]
    
    app = pywinauto.Application().start(anmezia_wg_path)
    # app = pywinauto.Application().connect(path=anmezia_wg_path, timeout=5)
    app = pywinauto.Application().connect(title="AmneziaWG", timeout=5)
    
    dialog = app.top_window()

    file_num = 0
    can_connect = False
    for n1 in cf_ports:
        file_num += 1
        endpoint_addr = f'188.114.99.224:{n1}'
        config_template[-1] = endpoint_wrapper(endpoint_addr)
        create_config(config_template, file_num)

        dialog['Toolbar'].click()

        dialog = app.top_window()
        dialog['&Имя файла:Edit'].set_edit_text(f'{root_dir_path}WARP{file_num}.conf')
        dialog['&ОткрытьButton'].click()

        dialog = app.top_window()
        dialog['Button'].click()

        while not dialog['Button'].is_enabled():
            sleep(1)

        attempts = 0
        while attempts < max_connection_retries:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((connection_check_host, 80))
                can_connect = True
                break
            except socket.error:
                attempts += 1
                sleep(1)

        dialog['Button'].click()

        if can_connect:
            print(endpoint_addr)
            break
        else:
            print('connection failed', endpoint_addr)
                
        # if can_connect:
        #     break
                    
