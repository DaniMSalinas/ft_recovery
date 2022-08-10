"""Main program for cyber forensic"""
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
        evidences = Recovery(re_logger, args.extended)
    else:
        evidences = Recovery(re_logger)
    print(evidences.data)

if __name__ == "__main__":
    main()
