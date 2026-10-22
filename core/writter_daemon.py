import os
import joblib
import logging
from scapy import sniff , TCP , IP , RAW
from db import int_db , int_insert_event

logging.basicConfig(level=logging.INFO, force="%(asctime)s [%(levelname)s] %(message)s")

