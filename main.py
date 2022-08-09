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
        print("Unknown args")
        return
    if args.minutes:
        evidences = Recovery(int(args.minutes) * 60)
    elif args.hours:
        evidences = Recovery(args.hours * 3600)
    elif args.days:
        evidences = Recovery(args.days * 86400)
    elif args.extended:
        evidences = Recovery(args.extended)
    else:
        evidences = Recovery()
    print(evidences)

if __name__ == "__main__":
    main()
