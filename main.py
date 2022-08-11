"""Main program for cyber forensic"""
from datetime import datetime
import time
from src.config import ConfigLibrary
from src.recovery import Recovery
from src.logger import RecoveryLogger

def main():
    """main function of recovery program"""
    config = ConfigLibrary()
    re_logger = RecoveryLogger()
    re_logger.set_log_level(config.get_log_level())

    try:
        args, unknown = config.parser.parse_known_args()
    except SystemExit:
        return

    if unknown:
        re_logger.logger.error("Unknown args")
        return
    if args.minutes:
        evidences = Recovery(re_logger, args.minutes * 60)
    elif args.hours:
        evidences = Recovery(re_logger, args.hours * 3600)
    elif args.days:
        evidences = Recovery(re_logger, args.days * 86400)
    elif args.extended:
        date = time.mktime(datetime.strptime(args.extended, "%d/%m/%y %H:%M:%S").timetuple())
        evidences = Recovery(re_logger, date)
    else:
        evidences = Recovery(re_logger)

    Recovery.save_evidences(re_logger, evidences)

if __name__ == "__main__":
    main()
