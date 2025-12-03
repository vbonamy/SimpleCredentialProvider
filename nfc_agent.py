#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import time

time.sleep(2)  # Simuler le temps de lecture

username = "vboxuser"  # ou récupéré depuis esup-nfc-tag-server

print(username, end='')  # Important: pas de \n à la fin si possible
sys.exit(0)  # 0 = succès
