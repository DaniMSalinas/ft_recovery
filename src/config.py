"""Module where is created ConfigLibrary"""
import argparse
import configparser

class ConfigLibrary:
    """Class in charge of load the config of the program"""
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="""Recovery:\nThis collect evidences on windows 10 system""")
        self.set_arguments()
        self.config = configparser.ConfigParser()
        self.config.read('configuration/recovery.config')

    def set_arguments(self):
        """This function sets the args of the program"""
        self.parser.add_argument('-m', '--minutes', metavar='<hours>', type=str,
        help="set the time interval to see the evidences.\nFormat MUST be in number of hours")
        self.parser.add_argument('-ho', '--hours', metavar='<hours>', type=str,
        help="set the time interval to see the evidences.\nFormat MUST be in number of hours")
        self.parser.add_argument('-d', '--days', metavar='<days>', type=str,
        help="set the time interval to see the evidences.\nFormat MUST be in number of days")
        self.parser.add_argument('-e', '--extended', metavar='<date>', type=str,
        help="set the time interval to see the evidences.\nFormat MUST be yyyy-MM-dd HH:mm:ss.SSS")

    def get_program_version(self):
        """function returns the current program version"""
        return self.config['program']['version']

    def get_log_level(self):
        """function returns the current log level"""
        return self.config['logger']['level']

    def set_log_level(self, level):
        """function updates the log level version"""
        self.config['logger']['level'] = level
