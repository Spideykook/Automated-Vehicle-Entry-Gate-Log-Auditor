import csv
import re
from datetime import datetime
from collections import defaultdict


class VehicleLogAuditor:

    def __init__(self):

        self.clean_records = []
        self.duplicate_records = []
        self.suspicious_records = []
        self.rejected_records = []

        self.previous_scans = {}
        self.vehicle_history = defaultdict(list)
        self.vehicle_count = defaultdict(int)

        self.total_records = 0
#Vehile Validation:
    def validate_vehicle(self, vehicle_no):

        pattern = r"^WB\d{2}[A-Z]{2}\d{4}$"

        if re.match(pattern, vehicle_no):
            return True
        else:
            return False
#Validate Device:
    def validate_device(self, device):
        pattern = r"^DEV\d{3}$"
        if re.match(pattern, device):
            return True
        else:
            return False
#Validate Timestamp:
    def validate_timestamp(self, timestamp):
        try:
            scan_dt = datetime.strptime(
                timestamp,
                "%d-%m-%Y %H:%M:%S"
            )
            return scan_dt
        except ValueError:
            return None
#Process the CSV file and categorize records
    def process_file(self):
        with open(
            "raw_vehicle_logs.csv",
            "r",
            newline=""
        ) as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.total_records += 1
                vehicle_no = row["vehicle_no"]
                gate_code = row["gate_code"]
                scan_type = row["scan_type"]
                scan_time = row["scan_time"]
                device = row["security_device"]

                if self.validate_vehicle(vehicle_no):
                    if self.validate_device(device):
                        scan_dt = self.validate_timestamp(scan_time)
                        if scan_dt:
                            self.vehicle_count[vehicle_no] += 1

                            key = (
                                vehicle_no,
                                scan_type,
                                device
                            )

                            is_duplicate = False

                            if key in self.previous_scans:

                                seconds = (
                                    scan_dt -
                                    self.previous_scans[key]
                                ).total_seconds()

                                if seconds <= 45:

                                    self.duplicate_records.append(row)

                                    is_duplicate = True

                            self.previous_scans[key] = scan_dt

                            if is_duplicate == False:

                                is_suspicious = False

                                for old_gate, old_time in self.vehicle_history[vehicle_no]:
                                    minutes = abs(
                                        (
                                            scan_dt -
                                            old_time
                                        ).total_seconds()
                                    ) / 60

                                    if (
                                        old_gate != gate_code
                                        and old_time.date() == scan_dt.date()
                                        and minutes <= 30
                                    ):

                                        is_suspicious = True
                                        break
                                self.vehicle_history[vehicle_no].append(
                                    (
                                        gate_code,
                                        scan_dt
                                    )
                                )
                                if is_suspicious:

                                    self.suspicious_records.append(row)
                                else:

                                    self.clean_records.append(row)
                        else:

                            self.rejected_records.append(row)
                    else:

                        self.rejected_records.append(row)
                else:

                    self.rejected_records.append(row)

    def generate_report(self):

        with open(
            "audit_summary.txt",
            "w"
        ) as report:

            report.write(
                "Vehicle Gate Log Audit Report\n"
            )

            report.write(
                "----------------------------------\n\n"
            )

            report.write(
                f"Total Records: {self.total_records}\n"
            )

            report.write(
                f"Clean Records: {len(self.clean_records)}\n"
            )

            report.write(
                f"Duplicate Records: {len(self.duplicate_records)}\n"
            )

            report.write(
                f"Suspicious Records: {len(self.suspicious_records)}\n"
            )

            report.write(
                f"Rejected Records: {len(self.rejected_records)}\n\n"
            )

            report.write(
                "Vehicle Wise Summary\n"
            )

            report.write(
                "-------------------------\n"
            )

            for vehicle, count in self.vehicle_count.items():

                report.write(
                    f"{vehicle} : {count} scans\n"
                )
    def export_csv_files(self):
        if len(self.clean_records) > 0:
            with open(
                "clean_records.csv",
                "w",
                newline=""
            ) as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=self.clean_records[0].keys()
                )
                writer.writeheader()

                writer.writerows(
                    self.clean_records
                )
        if len(self.rejected_records) > 0:
            with open(
                "rejected_records.csv",
                "w",
                newline=""
            ) as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=self.rejected_records[0].keys()
                )
                writer.writeheader()
                writer.writerows(
                    self.rejected_records
                )
auditor = VehicleLogAuditor()
auditor.process_file()
auditor.generate_report()
auditor.export_csv_files()
print("Audit Completed Successfully")
print("Check audit_summary.txt")