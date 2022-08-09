"""forensic function to analyse"""
import winreg
import sqlite3
import os
import time
from datetime import datetime
import wmi
import pandas

class Recovery():
    """Recovery Class where it's stored all the data"""
    def __init__(self, logger, time_interval=86400):
        """Constructor of Recovery Class"""
        timestamp = datetime.now()
        self.time_interval = datetime.timestamp(timestamp) - time_interval
        self.data = {}
        self.windows_mi = wmi.WMI()
        self.logger = logger
        self._set_current_version_run()
        self._set_recent_files()
        self._set_installed_program()
        self._set_running_programs()
        self._set_navigation_historial()
        self._set_connected_devices()
        self._set_log_events()

    def _set_current_version_run(self):
        """Function returns the date of branchs change"""
        self.logger.logger.info("Retrieving current version run evidences")
        self.data['current_version_run'] = {}
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        reg_win_ts = winreg.QueryInfoKey(key)[2]
        reg_key_ts = self.windows_ticks_to_unix_seconds(reg_win_ts)
        if reg_key_ts > self.time_interval:
            self.data['current_version_run']['date'] = reg_key_ts

    def _set_recent_files(self):
        """Function returns recent files"""
        self.logger.logger.info("Retrieving recent files evidences")
        self.data["recent_files"] = []
        recent_files_path = os.getenv('APPDATA') + "\\Microsoft\\Windows\\Recent"
        for root, directory, files in os.walk(recent_files_path):
            for file in files:
                file_dict = {}
                file_path = root + '\\' + file
                file_dict["name"] = file.split('.lnk')[0]
                file_dict["date"] = os.path.getmtime(file_path)
                if os.path.getmtime(file_path) > self.time_interval:
                    self.data["recent_files"].append(file_dict)

    def _set_installed_program(self):
        """Function returns installed software in Windows"""
        self.logger.logger.info("Retrieving installed programs evidences")
        self.data["installed_programs"] = []
        self.data["installed_programs"].append(Recovery.subkeys_iterator(winreg.HKEY_LOCAL_MACHINE,
                                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                                    self.time_interval)[0])
        self.data["installed_programs"].append(Recovery.subkeys_iterator(winreg.HKEY_CURRENT_USER,
                                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                                    self.time_interval)[0])

    def _set_running_programs(self):
        """Function returns running programs in Windows"""
        self.logger.logger.info("Retrieving running programs evidences")
        self.data["running_processes"] = []
        for process in self.windows_mi.Win32_Process():
            process_dict = {}
            if process.HandleCount > 0:
                process_dict["name"] = process.Name
                process_dict["pid"] = process.ProcessId
                date = process.CreationDate
                process_dict["date"] = time.mktime(datetime.strptime(
                                        date.split('.')[0],'%Y%m%d%H%M%S').timetuple())
                if process_dict["date"] > self.time_interval:
                    self.data["running_processes"].append(process_dict)

    def _set_navigation_historial(self):
        """Function returns the navigation historial on Windows"""
        self.logger.logger.info("Retrieving navigation historial evidences")
        self.data["navigation_historical"] = []
        navigator_name = Recovery.subkeys_iterator(winreg.HKEY_LOCAL_MACHINE,
        "Software\\Clients\\StartMenuInternet", self.time_interval)[1]
        for navigator in navigator_name:
            if "Firefox" in navigator:
                navigator_dir = os.getenv('APPDATA')+"\\Mozilla\\Firefox\\Profiles"
                for profile_dir in os.listdir(navigator_dir):
                    if "default-release" in profile_dir:
                        profile = profile_dir
                self.get_db_info(navigator_dir + "\\" + profile, "places.sqlite", navigator)
            elif "Google" in navigator:
                navigator_dir = os.getenv('LOCALAPPDATA') + "\\Google\\Chrome\\User Data\\Default"
                self.get_db_info(navigator_dir, "History", navigator)
            elif "Microsoft" in navigator:
                navigator_dir = os.getenv('LOCALAPPDATA') + "\\Microsoft\\Edge\\User Data\\Default"
                self.get_db_info(navigator_dir, "History", navigator)

    def _set_connected_devices(self):
        """Function returns connected devices"""
        self.logger.logger.info("Retrieving connected devices evidences")
        self.data["connected_devices"] = []
        for item in self.windows_mi.Win32_PnPEntity():
            devices_dict = {}
            devices_dict["name"] = item.Name
            devices_dict["type"] = item.PNPClass
            devices_dict["id"] = item.DeviceID
            self.data["connected_devices"].append(devices_dict)

    def _set_log_events(self):
        """Function returns log events"""
        self.logger.logger.info("Retrieving log events evidences")
        self.data["log_events"] = []
        for log in self.windows_mi.Win32_NTLogEvent(EventType=1):
            logs_dict = {}
            logs_dict["name"] = log.SourceName
            logs_dict["type"] = log.Type
            date = log.TimeWritten
            logs_dict["date"] = time.mktime(datetime.strptime(
                                        date.split('.')[0],'%Y%m%d%H%M%S').timetuple())
            logs_dict["message"] = log.Message
            logs_dict["logfile"] = log.Logfile
            logs_dict["user"] = log.User
            if logs_dict["date"] > self.time_interval:
                self.data["log_events"].append(logs_dict)

    def get_db_info(self, db_path, db_name, navigator):
        """Fucntion returns a dictionary with history url visited on web navigator"""
        try:
            db_query = Recovery.get_query(db_path, db_name, navigator)
        except sqlite3.DatabaseError:
            self.logger.logger.warning(navigator + "database is locked, unable to read. Skiping")
            return
        for element in db_query.values:
            navigator_dict = {}
            navigator_dict["navigator"] = navigator
            navigator_dict["url"] = element[0]
            if "Firefox" in navigator:
                navigator_dict["date"] = element[1]
            else:
                navigator_dict["date"] = (element[1] /1000000) - 11644473600
            if navigator_dict["date"] > self.time_interval:
                self.data["navigation_historical"] = [].append(navigator_dict)

    @staticmethod
    def windows_ticks_to_unix_seconds(windows_ticks):
        """function translate to unix seconds"""
        return windows_ticks/10000000 - 11644473600

    @staticmethod
    def subkeys_iterator(hkey, path, time_interval):
        """function that iterates over winreg subkeys"""
        keys_list = []
        name_list = []
        key = winreg.OpenKey(hkey, path)
        subkeys_list = winreg.QueryInfoKey(key)[0]
        for subkey in range (subkeys_list):
            program = {}
            try:
                subkey_name = winreg.EnumKey(key, subkey)
                subkey_open = winreg.OpenKey(key, subkey_name)
                program["name"] = winreg.QueryValueEx(subkey_open, "DisplayName")[0]
                modification_date = winreg.QueryInfoKey(subkey_open)[2]
                unix_date = Recovery.windows_ticks_to_unix_seconds(modification_date)
                program["date"] = unix_date
                if unix_date > time_interval:
                    keys_list.append(program)
            except FileNotFoundError:
                name_list.append(subkey_name)
            except EnvironmentError:
                continue
        return keys_list, name_list

    @staticmethod
    def get_query(db_path, db_name, navigator):
        """Function returns query info of web browser db"""
        db_connection = sqlite3.connect(db_path + "\\" + db_name)
        if "Firefox" in navigator:
            db_query = pandas.read_sql_query(
                "SELECT url, visit_date from moz_places, moz_historyvisits", db_connection)
        else:
            try:
                db_query = pandas.read_sql_query(
                    "SELECT url, last_visit_time from urls", db_connection)
            except Exception as exc:
                raise sqlite3.DatabaseError from exc
        return db_query
