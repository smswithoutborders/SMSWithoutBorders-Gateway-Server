#!/bin/bash


curl -X POST http://localhost:5000/sms/platform/twilio/incoming/protocol/verification -F 'From=0237000000000'  -F 'To=0237111111111' -F 'FromCountry=CM' -F 'NumSegments=1' -F 'Body=eyJJTVNJIjogIjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAifQ=='
