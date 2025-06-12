# utils/logger.py

import logging
import sys

class ReconLogger:
    def __init__(self):
        self.logger = logging.getLogger("recon")
        self.logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S"
        ))
        self.logger.addHandler(handler)

    def info(self, msg): self.logger.info(msg)
    def warning(self, msg): self.logger.warning(msg)
    def error(self, msg): self.logger.error(msg)
    def success(self, msg): self.logger.info(f"[+] {msg}")
    def debug(self, msg): self.logger.debug(msg)
    def exception(self, msg): self.logger.exception(msg)

recon_logger = ReconLogger()
