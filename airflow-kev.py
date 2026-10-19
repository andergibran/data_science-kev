from airflow import DAG
from airflow.operators.python import PythonOperator

from datetime import datetime
import requests
import mysql.connector
import time


# ============================================================
# CONFIG
# ============================================================

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EPSS_URL = "https://api.first.org/data/v1/epss"


# ============================================================
# MASUKKAN API KEY NVD 
# ============================================================

NVD_API_KEY = "API KEY NVD"


MYSQL_CONFIG = {
    "host": "host.docker.internal",
    "port": 3307,
    "user": "root",
    "password": "root",
    "database": "airflow_db"
}


# ============================================================
# TASK 1 - CISA KEV
# ============================================================

def extract_transform_load_kev():

    print("Mengambil data dari CISA KEV...")

    response = requests.get(
        CISA_URL,
        timeout=60
    )

    response.raise_for_status()

    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])

    print(
        f"Jumlah vulnerability dari CISA: "
        f"{len(vulnerabilities)}"
    )

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor()

    # --------------------------------------------------------
    # CREATE TABLE KEV
    # --------------------------------------------------------

    create_table_sql = """
    CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
        cveID VARCHAR(30) PRIMARY KEY,
        vendorProject VARCHAR(255),
        product TEXT,
        vulnerabilityName TEXT,
        dateAdded DATE,
        shortDescription TEXT,
        requiredAction TEXT,
        dueDate DATE,
        knownRansomwareCampaignUse VARCHAR(20),
        forensicTriage TEXT,
        notes TEXT,
        cwes TEXT
    )
    """

    cursor.execute(create_table_sql)

    # --------------------------------------------------------
    # INSERT / UPDATE KEV
    # --------------------------------------------------------

    insert_sql = """
    INSERT INTO kev_vulnerabilities (
        cveID,
        vendorProject,
        product,
        vulnerabilityName,
        dateAdded,
        shortDescription,
        requiredAction,
        dueDate,
        knownRansomwareCampaignUse,
        forensicTriage,
        notes,
        cwes
    )
    VALUES (
        %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
        vendorProject = VALUES(vendorProject),
        product = VALUES(product),
        vulnerabilityName = VALUES(vulnerabilityName),
        dateAdded = VALUES(dateAdded),
        shortDescription = VALUES(shortDescription),
        requiredAction = VALUES(requiredAction),
        dueDate = VALUES(dueDate),
        knownRansomwareCampaignUse = VALUES(knownRansomwareCampaignUse),
        forensicTriage = VALUES(forensicTriage),
        notes = VALUES(notes),
        cwes = VALUES(cwes)
    """

    total = 0

    # --------------------------------------------------------
    # PROCESS KEV
    # --------------------------------------------------------

    for item in vulnerabilities:

        cve_id = item.get("cveID")
        vendor_project = item.get("vendorProject")
        product = item.get("product")
        vulnerability_name = item.get("vulnerabilityName")

        date_added = item.get("dateAdded")
        short_description = item.get("shortDescription")
        required_action = item.get("requiredAction")
        due_date = item.get("dueDate")

        ransomware = item.get(
            "knownRansomwareCampaignUse"
        )

        forensic_triage = item.get("forensicTriage")
        notes = item.get("notes")
        cwes = item.get("cwes")

        if isinstance(cwes, list):
            cwes = ", ".join(cwes)

        values = (
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            short_description,
            required_action,
            due_date,
            ransomware,
            forensic_triage,
            notes,
            cwes
        )

        cursor.execute(
            insert_sql,
            values
        )

        total += 1

        if total % 100 == 0:

            conn.commit()

            print(
                f"KEV: {total} data diproses..."
            )

    conn.commit()

    cursor.close()
    conn.close()

    print(
        f"KEV selesai. "
        f"Total data diproses: {total}"
    )


# ============================================================
# TASK 2 - NVD ENRICHMENT
# ============================================================

def extract_load_nvd():

    print("Memulai enrichment NVD...")

    # ========================================================
    # AMBIL CVE DARI KEV
    # ========================================================

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT cveID
        FROM kev_vulnerabilities
        ORDER BY cveID
    """)

    kev_cves = [
        row[0]
        for row in cursor.fetchall()
    ]

    print(
        f"Total CVE dari KEV: "
        f"{len(kev_cves)}"
    )

    # ========================================================
    # AMBIL CVE YANG SUDAH ADA DI NVD
    # ========================================================

    cursor.execute("""
        SELECT cveID
        FROM nvd_vulnerabilities
    """)

    existing_cves = {
        row[0]
        for row in cursor.fetchall()
    }

    print(
        f"CVE yang sudah ada di NVD: "
        f"{len(existing_cves)}"
    )

    # ========================================================
    # FILTER CVE YANG BELUM ADA
    # ========================================================

    cves_to_process = [
        cve
        for cve in kev_cves
        if cve not in existing_cves
    ]

    print(
        f"CVE yang masih perlu diambil: "
        f"{len(cves_to_process)}"
    )

    if not cves_to_process:

        print(
            "Tidak ada CVE baru. "
            "Tabel NVD sudah up to date."
        )

        cursor.close()
        conn.close()

        return

    # ========================================================
    # CREATE TABLE NVD
    # ========================================================

    create_table_sql = """
    CREATE TABLE IF NOT EXISTS nvd_vulnerabilities (
        cveID VARCHAR(30) PRIMARY KEY,
        description TEXT,
        published DATETIME,
        lastModified DATETIME,

        cvssScore DECIMAL(3,1),
        severity VARCHAR(20),

        attackVector VARCHAR(30),
        attackComplexity VARCHAR(20),
        privilegesRequired VARCHAR(20),
        userInteraction VARCHAR(20),

        scope VARCHAR(20),
        confidentialityImpact VARCHAR(20),
        integrityImpact VARCHAR(20),
        availabilityImpact VARCHAR(20),

        cwe TEXT,

        FOREIGN KEY (cveID)
            REFERENCES kev_vulnerabilities(cveID)
    )
    """

    cursor.execute(create_table_sql)
    conn.commit()

    # ========================================================
    # SQL INSERT / UPDATE
    # ========================================================

    insert_sql = """
    INSERT INTO nvd_vulnerabilities (
        cveID,
        description,
        published,
        lastModified,

        cvssScore,
        severity,

        attackVector,
        attackComplexity,
        privilegesRequired,
        userInteraction,

        scope,
        confidentialityImpact,
        integrityImpact,
        availabilityImpact,

        cwe
    )
    VALUES (
        %s, %s, %s, %s,
        %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s
    )
    ON DUPLICATE KEY UPDATE

        description = VALUES(description),
        published = VALUES(published),
        lastModified = VALUES(lastModified),

        cvssScore = VALUES(cvssScore),
        severity = VALUES(severity),

        attackVector = VALUES(attackVector),
        attackComplexity = VALUES(attackComplexity),
        privilegesRequired = VALUES(privilegesRequired),
        userInteraction = VALUES(userInteraction),

        scope = VALUES(scope),
        confidentialityImpact = VALUES(confidentialityImpact),
        integrityImpact = VALUES(integrityImpact),
        availabilityImpact = VALUES(availabilityImpact),

        cwe = VALUES(cwe)
    """

    # ========================================================
    # HTTP SESSION
    # ========================================================

    session = requests.Session()

    headers = {
        "apiKey": NVD_API_KEY,
        "User-Agent": "Airflow-CISA-KEV-ETL"
    }

    # ========================================================
    # COUNTERS
    # ========================================================

    success_count = 0
    not_found_count = 0
    failed_cves = []
    saved_count = 0

    # ========================================================
    # REQUEST NVD ONE BY ONE
    # ========================================================

    for index, cve_id in enumerate(
        cves_to_process,
        start=1
    ):

        print(
            f"[{index}/{len(cves_to_process)}] "
            f"Mengambil NVD: {cve_id}"
        )

        params = {
            "cveId": cve_id
        }

        success = False
        cve_data = None

        # ====================================================
        # MAX 3 RETRY
        # ====================================================

        for attempt in range(1, 4):

            try:

                response = session.get(
                    NVD_URL,
                    params=params,
                    headers=headers,
                    timeout=30
                )

                # ------------------------------------------------
                # RATE LIMIT
                # ------------------------------------------------

                if response.status_code == 429:

                    wait_time = 15 * attempt

                    print(
                        f"{cve_id}: HTTP 429. "
                        f"Menunggu {wait_time} detik..."
                    )

                    time.sleep(wait_time)

                    continue

                response.raise_for_status()

                data = response.json()

                vulnerabilities = data.get(
                    "vulnerabilities",
                    []
                )

                # ------------------------------------------------
                # CVE DITEMUKAN
                # ------------------------------------------------

                if vulnerabilities:

                    cve_data = vulnerabilities[0].get(
                        "cve",
                        {}
                    )

                    success_count += 1

                    print(
                        f"{cve_id}: berhasil."
                    )

                # ------------------------------------------------
                # CVE TIDAK DITEMUKAN
                # ------------------------------------------------

                else:

                    not_found_count += 1

                    print(
                        f"{cve_id}: "
                        f"tidak ditemukan di NVD."
                    )

                success = True

                break

            # ----------------------------------------------------
            # TIMEOUT
            # ----------------------------------------------------

            except requests.exceptions.Timeout:

                print(
                    f"{cve_id}: timeout "
                    f"(percobaan {attempt}/3)"
                )

                if attempt < 3:

                    wait_time = 5 * attempt

                    print(
                        f"Menunggu {wait_time} detik..."
                    )

                    time.sleep(wait_time)

            # ----------------------------------------------------
            # REQUEST ERROR
            # ----------------------------------------------------

            except requests.exceptions.RequestException as e:

                print(
                    f"{cve_id}: request error "
                    f"(percobaan {attempt}/3): {e}"
                )

                if attempt < 3:

                    wait_time = 5 * attempt

                    print(
                        f"Menunggu {wait_time} detik..."
                    )

                    time.sleep(wait_time)

            # ----------------------------------------------------
            # ERROR LAIN
            # ----------------------------------------------------

            except Exception as e:

                print(
                    f"{cve_id}: "
                    f"error tidak terduga: {e}"
                )

                break

        # ========================================================
        # GAGAL SETELAH 3 RETRY
        # ========================================================

        if not success:

            print(
                f"{cve_id}: GAGAL setelah 3 percobaan."
            )

            failed_cves.append(cve_id)

            time.sleep(2)

            continue

        # ========================================================
        # JIKA TIDAK ADA DATA, LANJUT
        # ========================================================

        if not cve_data:

            time.sleep(2)

            continue

        # ========================================================
        # EXTRACT DESCRIPTION
        # ========================================================

        description = None

        descriptions = cve_data.get(
            "descriptions",
            []
        )

        for desc in descriptions:

            if desc.get("lang") == "en":

                description = desc.get(
                    "value"
                )

                break

        # ========================================================
        # DATE
        # ========================================================

        published = cve_data.get(
            "published"
        )

        last_modified = cve_data.get(
            "lastModified"
        )

        # ========================================================
        # CVSS
        # ========================================================

        cvss_score = None
        severity = None

        attack_vector = None
        attack_complexity = None
        privileges_required = None
        user_interaction = None

        scope = None
        confidentiality_impact = None
        integrity_impact = None
        availability_impact = None

        metrics = cve_data.get(
            "metrics",
            {}
        )

        cvss_metric = None

        # Prioritas CVSS 3.1
        if metrics.get("cvssMetricV31"):

            cvss_metric = metrics[
                "cvssMetricV31"
            ][0]

        # Fallback CVSS 3.0
        elif metrics.get("cvssMetricV30"):

            cvss_metric = metrics[
                "cvssMetricV30"
            ][0]

        if cvss_metric:

            cvss_data = cvss_metric.get(
                "cvssData",
                {}
            )

            cvss_score = cvss_data.get(
                "baseScore"
            )

            severity = cvss_data.get(
                "baseSeverity"
            )

            attack_vector = cvss_data.get(
                "attackVector"
            )

            attack_complexity = cvss_data.get(
                "attackComplexity"
            )

            privileges_required = cvss_data.get(
                "privilegesRequired"
            )

            user_interaction = cvss_data.get(
                "userInteraction"
            )

            scope = cvss_data.get(
                "scope"
            )

            confidentiality_impact = cvss_data.get(
                "confidentialityImpact"
            )

            integrity_impact = cvss_data.get(
                "integrityImpact"
            )

            availability_impact = cvss_data.get(
                "availabilityImpact"
            )

        # ========================================================
        # CWE
        # ========================================================

        cwe_values = []

        weaknesses = cve_data.get(
            "weaknesses",
            []
        )

        for weakness in weaknesses:

            descriptions = weakness.get(
                "description",
                []
            )

            for item in descriptions:

                value = item.get(
                    "value"
                )

                if value:

                    cwe_values.append(
                        value
                    )

        cwe = ", ".join(
            sorted(set(cwe_values))
        )

        # ========================================================
        # CONVERT DATE FORMAT
        # ========================================================

        if published:

            published = published.replace(
                "T",
                " "
            )

            if "." in published:

                published = published.split(
                    "."
                )[0]

            if published.endswith("Z"):

                published = published[:-1]

        if last_modified:

            last_modified = last_modified.replace(
                "T",
                " "
            )

            if "." in last_modified:

                last_modified = last_modified.split(
                    "."
                )[0]

            if last_modified.endswith("Z"):

                last_modified = last_modified[:-1]

        # ========================================================
        # INSERT IMMEDIATELY KE MYSQL
        # ========================================================

        values = (
            cve_id,
            description,
            published,
            last_modified,

            cvss_score,
            severity,

            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,

            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,

            cwe
        )

        try:

            cursor.execute(
                insert_sql,
                values
            )

            conn.commit()

            saved_count += 1

            print(
                f"MySQL: {cve_id} berhasil disimpan. "
                f"Total tersimpan: {saved_count}"
            )

        except mysql.connector.Error as e:

            print(
                f"MySQL error untuk {cve_id}: {e}"
            )

            conn.rollback()

            failed_cves.append(
                cve_id
            )

        # ========================================================
        # JEDA REQUEST
        # ========================================================

        time.sleep(2)

    # ============================================================
    # CLOSE CONNECTION
    # ============================================================

    session.close()

    cursor.close()
    conn.close()

    # ============================================================
    # SUMMARY
    # ============================================================

    print("=" * 60)

    print("NVD ENRICHMENT SELESAI")

    print(
        f"Berhasil dari NVD : {success_count}"
    )

    print(
        f"Tidak ditemukan   : {not_found_count}"
    )

    print(
        f"Disimpan ke MySQL : {saved_count}"
    )

    print(
        f"Gagal total       : {len(failed_cves)}"
    )

    if failed_cves:

        print("CVE yang gagal:")

        for cve in failed_cves:

            print(
                f" - {cve}"
            )

    print("=" * 60)


# ============================================================
# TASK 3 - EPSS ENRICHMENT
# ============================================================

def extract_load_epss():

    print("Memulai enrichment EPSS...")

    # ========================================================
    # AMBIL CVE DARI KEV
    # ========================================================

    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT cveID
        FROM kev_vulnerabilities
        ORDER BY cveID
    """)

    kev_cves = [
        row[0]
        for row in cursor.fetchall()
    ]

    print(
        f"Total CVE dari KEV: "
        f"{len(kev_cves)}"
    )

    # ========================================================
    # AMBIL CVE YANG SUDAH ADA DI EPSS
    # ========================================================

    cursor.execute("""
        SELECT cveID
        FROM epss_vulnerabilities
    """)

    existing_cves = {
        row[0]
        for row in cursor.fetchall()
    }

    print(
        f"CVE yang sudah ada di EPSS: "
        f"{len(existing_cves)}"
    )

    # ========================================================
    # FILTER CVE YANG BELUM ADA
    # ========================================================

    cves_to_process = [
        cve
        for cve in kev_cves
        if cve not in existing_cves
    ]

    print(
        f"CVE yang masih perlu diambil: "
        f"{len(cves_to_process)}"
    )

    if not cves_to_process:

        print(
            "Tidak ada CVE baru. "
            "Tabel EPSS sudah up to date."
        )

        cursor.close()
        conn.close()

        return

    # ========================================================
    # CREATE TABLE EPSS
    # ========================================================

    create_table_sql = """
    CREATE TABLE IF NOT EXISTS epss_vulnerabilities (
        cveID VARCHAR(30) PRIMARY KEY,
        epssScore DECIMAL(10,8),
        percentile DECIMAL(10,8),
        scoreDate DATE,

        FOREIGN KEY (cveID)
            REFERENCES kev_vulnerabilities(cveID)
    )
    """

    cursor.execute(create_table_sql)
    conn.commit()

    # ========================================================
    # SQL INSERT / UPDATE
    # ========================================================

    insert_sql = """
    INSERT INTO epss_vulnerabilities (
        cveID,
        epssScore,
        percentile,
        scoreDate
    )
    VALUES (
        %s, %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
        epssScore = VALUES(epssScore),
        percentile = VALUES(percentile),
        scoreDate = VALUES(scoreDate)
    """

    # ========================================================
    # HTTP SESSION
    # ========================================================

    session = requests.Session()

    # ========================================================
    # COUNTERS
    # ========================================================

    success_count = 0
    not_found_count = 0
    failed_cves = []
    saved_count = 0

    # ========================================================
    # REQUEST EPSS
    # ========================================================

    for index, cve_id in enumerate(
        cves_to_process,
        start=1
    ):

        print(
            f"[{index}/{len(cves_to_process)}] "
            f"Mengambil EPSS: {cve_id}"
        )

        params = {
            "cve": cve_id
        }

        success = False
        epss_data = None

        # ====================================================
        # MAX 3 RETRY
        # ====================================================

        for attempt in range(1, 4):

            try:

                response = session.get(
                    EPSS_URL,
                    params=params,
                    timeout=30
                )

                # ------------------------------------------------
                # RATE LIMIT
                # ------------------------------------------------

                if response.status_code == 429:

                    wait_time = 10 * attempt

                    print(
                        f"{cve_id}: HTTP 429. "
                        f"Menunggu {wait_time} detik..."
                    )

                    time.sleep(wait_time)

                    continue

                response.raise_for_status()

                data = response.json()

                epss_results = data.get(
                    "data",
                    []
                )

                # ------------------------------------------------
                # DATA DITEMUKAN
                # ------------------------------------------------

                if epss_results:

                    epss_data = epss_results[0]

                    success_count += 1

                    print(
                        f"{cve_id}: EPSS berhasil."
                    )

                # ------------------------------------------------
                # DATA TIDAK DITEMUKAN
                # ------------------------------------------------

                else:

                    not_found_count += 1

                    print(
                        f"{cve_id}: "
                        f"tidak ditemukan di EPSS."
                    )

                success = True

                break

            # ----------------------------------------------------
            # TIMEOUT
            # ----------------------------------------------------

            except requests.exceptions.Timeout:

                print(
                    f"{cve_id}: timeout "
                    f"(percobaan {attempt}/3)"
                )

                if attempt < 3:

                    wait_time = 5 * attempt

                    print(
                        f"Menunggu {wait_time} detik..."
                    )

                    time.sleep(wait_time)

            # ----------------------------------------------------
            # REQUEST ERROR
            # ----------------------------------------------------

            except requests.exceptions.RequestException as e:

                print(
                    f"{cve_id}: request error "
                    f"(percobaan {attempt}/3): {e}"
                )

                if attempt < 3:

                    wait_time = 5 * attempt

                    print(
                        f"Menunggu {wait_time} detik..."
                    )

                    time.sleep(wait_time)

            # ----------------------------------------------------
            # ERROR LAIN
            # ----------------------------------------------------

            except Exception as e:

                print(
                    f"{cve_id}: "
                    f"error tidak terduga: {e}"
                )

                break

        # ========================================================
        # GAGAL SETELAH 3 RETRY
        # ========================================================

        if not success:

            print(
                f"{cve_id}: GAGAL setelah 3 percobaan."
            )

            failed_cves.append(cve_id)

            continue

        # ========================================================
        # JIKA DATA TIDAK ADA
        # ========================================================

        if not epss_data:

            time.sleep(1)

            continue

        # ========================================================
        # EXTRACT EPSS
        # ========================================================

        cve_result = epss_data.get(
            "cve"
        )

        epss_score = epss_data.get(
            "epss"
        )

        percentile = epss_data.get(
            "percentile"
        )

        score_date = epss_data.get(
            "date"
        )

        # ========================================================
        # INSERT KE MYSQL
        # ========================================================

        values = (
            cve_result,
            epss_score,
            percentile,
            score_date
        )

        try:

            cursor.execute(
                insert_sql,
                values
            )

            conn.commit()

            saved_count += 1

            print(
                f"MySQL: {cve_result} berhasil disimpan. "
                f"EPSS = {epss_score}, "
                f"Percentile = {percentile}, "
                f"Total tersimpan: {saved_count}"
            )

        except mysql.connector.Error as e:

            print(
                f"MySQL error untuk {cve_id}: {e}"
            )

            conn.rollback()

            failed_cves.append(
                cve_id
            )

        # ========================================================
        # JEDA REQUEST
        # ========================================================

        time.sleep(1)

    # ============================================================
    # CLOSE CONNECTION
    # ============================================================

    session.close()

    cursor.close()
    conn.close()

    # ============================================================
    # SUMMARY
    # ============================================================

    print("=" * 60)

    print("EPSS ENRICHMENT SELESAI")

    print(
        f"Berhasil dari EPSS : {success_count}"
    )

    print(
        f"Tidak ditemukan    : {not_found_count}"
    )

    print(
        f"Disimpan ke MySQL  : {saved_count}"
    )

    print(
        f"Gagal total        : {len(failed_cves)}"
    )

    if failed_cves:

        print("CVE yang gagal:")

        for cve in failed_cves:

            print(
                f" - {cve}"
            )

    print("=" * 60)


# ============================================================
# AIRFLOW DAG
# ============================================================

with DAG(
    dag_id="cisa_kev_etl",

    start_date=datetime(
        2026,
        1,
        1
    ),

    schedule=None,

    catchup=False,

    tags=[
        "cisa",
        "kev",
        "nvd",
        "epss",
        "cybersecurity"
    ]

) as dag:

    kev = PythonOperator(
        task_id="extract_transform_load_kev",
        python_callable=extract_transform_load_kev
    )

    nvd = PythonOperator(
        task_id="extract_load_nvd",
        python_callable=extract_load_nvd
    )

    epss = PythonOperator(
        task_id="extract_load_epss",
        python_callable=extract_load_epss
    )

    kev >> nvd >> epss