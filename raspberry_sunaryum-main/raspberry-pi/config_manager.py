import configparser
import os
import logging

logger = logging.getLogger('ConfigManager')

class ConfigManager:
    def __init__(self, config_path='config.ini'):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._create_default_config()
        self.load_config()
        
    def _create_default_config(self):
        if not os.path.exists(self.config_path):
            self.config['Wallet'] = {'seed_phrase': ''}
            self.config['Network'] = {
                'listen_port': '5000',
                'broadcast_ip': '224.0.0.114',
                'broadcast_port': '5001'
            }
            self.config['Prototype'] = {
                'read_interval': '10',
                'send_interval': '60'
            }
            self.config['Settings'] = {
                'timezone': 'America/Sao_Paulo',
                'log_level': 'INFO'
            }
            with open(self.config_path, 'w') as configfile:
                self.config.write(configfile)
            logger.info(f"Arquivo de configuração criado: {self.config_path}")
            
    def load_config(self):
        self.config.read(self.config_path)
        
    def get_seed_phrase(self):
        return self.config.get('Wallet', 'seed_phrase').strip()
    
    def get_network_setting(self, key, default=None, cast=str):
        try:
            value = self.config.get('Network', key)
            return cast(value) if cast else value
        except:
            return default
    
    def get_read_interval(self):
        try:
            return int(self.config.get('Prototype', 'read_interval'))
        except:
            return 10
    
    def get_send_interval(self):
        try:
            return int(self.config.get('Prototype', 'send_interval'))
        except:
            return 60
    
    def get_log_level(self):
        level_str = self.config.get('Settings', 'log_level', fallback='INFO').upper()
        return getattr(logging, level_str, logging.INFO)