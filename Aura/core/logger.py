from colorama import Fore, Style, init

init(autoreset=True)

class Logger:
    @staticmethod
    def info(msg): print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")
    @staticmethod
    def success(msg): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
    @staticmethod
    def warn(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    @staticmethod
    def critical(msg): print(f"{Fore.RED}[CRITICAL]{Style.BOLD} {msg}")
    @staticmethod
    def error(msg): print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")