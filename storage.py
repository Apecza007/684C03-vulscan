import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

# กำหนดที่เก็บฐานข้อมูล
DB_PATH = Path("scan_results.db")


def init_db() -> None:
    """
    สร้างฐานข้อมูลและตารางถ้ายังไม่มี
    
    สร้างตาราง scan_runs สำหรับเก็บประวัติการสแกนทั้งหมด
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            scan_mode TEXT NOT NULL,
            tools TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(
    *,
    target: str,
    target_type: str,
    scan_mode: str,
    tools: list[str],
    created_at: str,
    result: dict[str, Any],
) -> int:
    """
    บันทึกผลการสแกนลงฐานข้อมูล
    
    Args:
        target: เป้าหมายที่สแกน
        target_type: ประเภทเป้าหมาย (ip, domain, url)
        scan_mode: โหมดการสแกน (quick, balanced, deep)
        tools: รายการเครื่องมือที่ใช้
        created_at: เวลาที่บันทึก
        result: ผลการสแกนทั้งหมด
    
    Returns:
        int: ID ของ record ที่บันทึก
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # บันทึกข้อมูล
    cursor.execute(
        """
        INSERT INTO scan_runs (target, target_type, scan_mode, tools, created_at, result_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            target,
            target_type,
            scan_mode,
            ",".join(tools),  # แปลง list เป็น string คั่นด้วย comma
            created_at,
            json.dumps(result, ensure_ascii=False),  # แปลง dict เป็น JSON
        ),
    )
    
    conn.commit()
    run_id = cursor.lastrowid
    conn.close()
    
    return int(run_id)


def get_scan(run_id: int) -> Optional[dict[str, Any]]:
    """
    ดึงข้อมูลการสแกนจากฐานข้อมูลตาม ID
    
    Args:
        run_id: ID ของการสแกนที่ต้องการ
    
    Returns:
        dict: ข้อมูลการสแกน หรือ None ถ้าไม่พบ
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # ทำให้เข้าถึงข้อมูลแบบ dict ได้
    
    row = conn.execute(
        "SELECT * FROM scan_runs WHERE id = ?", 
        (run_id,)
    ).fetchone()
    
    conn.close()
    
    if row is None:
        return None

    # แปลงข้อมูลจากฐานข้อมูลเป็น dict
    return {
        "id": row["id"],
        "target": row["target"],
        "target_type": row["target_type"],
        "scan_mode": row["scan_mode"],
        "tools": row["tools"].split(",") if row["tools"] else [],
        "created_at": row["created_at"],
        "result": json.loads(row["result_json"]),  # แปลง JSON กลับเป็น dict
    }


def get_all_scans(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """
    ดึงประวัติการสแกนทั้งหมด แบบแบ่งหน้า
    
    Args:
        limit: จำนวนรายการต่อหน้า
        offset: ตำแหน่งเริ่มต้น
    
    Returns:
        list: รายการประวัติการสแกน
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute(
        """
        SELECT id, target, target_type, scan_mode, created_at 
        FROM scan_runs 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
        """,
        (limit, offset)
    ).fetchall()
    
    conn.close()
    
    return [dict(row) for row in rows]


def count_scans() -> int:
    """
    นับจำนวนการสแกนทั้งหมดในฐานข้อมูล
    
    Returns:
        int: จำนวนรายการทั้งหมด
    """
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute("SELECT COUNT(*) as count FROM scan_runs").fetchone()[0]
    conn.close()
    
    return count


def delete_scan(run_id: int) -> bool:
    """
    ลบประวัติการสแกนตาม ID
    
    Args:
        run_id: ID ของการสแกนที่ต้องการลบ
    
    Returns:
        bool: True ถ้าลบสำเร็จ, False ถ้าไม่พบรายการ
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("DELETE FROM scan_runs WHERE id = ?", (run_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    
    return deleted


def clear_all_scans() -> int:
    """
    ล้างประวัติการสแกนทั้งหมด
    
    Returns:
        int: จำนวนรายการที่ถูกลบ
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("DELETE FROM scan_runs")
    conn.commit()
    count = cursor.rowcount
    conn.close()
    
    return count


def get_scans_by_date(date: str) -> list[dict[str, Any]]:
    """
    ดึงประวัติการสแกนตามวันที่
    
    Args:
        date: วันที่ต้องการ (รูปแบบ YYYY-MM-DD)
    
    Returns:
        list: รายการประวัติการสแกนในวันที่ระบุ
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute(
        """
        SELECT id, target, target_type, scan_mode, created_at 
        FROM scan_runs 
        WHERE date(created_at) = ?
        ORDER BY created_at DESC
        """,
        (date,)
    ).fetchall()
    
    conn.close()
    
    return [dict(row) for row in rows]


def get_scans_by_target(target: str) -> list[dict[str, Any]]:
    """
    ค้นหาประวัติการสแกนตามเป้าหมาย
    
    Args:
        target: เป้าหมายที่ต้องการค้นหา
    
    Returns:
        list: รายการประวัติการสแกนที่ตรงกับเป้าหมาย
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute(
        """
        SELECT id, target, target_type, scan_mode, created_at 
        FROM scan_runs 
        WHERE target LIKE ?
        ORDER BY created_at DESC
        """,
        (f"%{target}%",)
    ).fetchall()
    
    conn.close()
    
    return [dict(row) for row in rows]


def get_stats() -> dict[str, Any]:
    """
    ดึงสถิติการใช้งาน
    
    Returns:
        dict: สถิติต่างๆ เช่น จำนวนการสแกนทั้งหมด, ค่าเฉลี่ย, etc.
    """
    conn = sqlite3.connect(DB_PATH)
    
    # นับจำนวนตามโหมด
    mode_stats = dict(conn.execute(
        "SELECT scan_mode, COUNT(*) FROM scan_runs GROUP BY scan_mode"
    ).fetchall())
    
    # นับจำนวนตามประเภทเป้าหมาย
    type_stats = dict(conn.execute(
        "SELECT target_type, COUNT(*) FROM scan_runs GROUP BY target_type"
    ).fetchall())
    
    # หาวันที่สแกนล่าสุด
    last_scan = conn.execute(
        "SELECT MAX(created_at) FROM scan_runs"
    ).fetchone()[0]
    
    total = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
    
    conn.close()
    
    return {
        "total_scans": total,
        "by_mode": mode_stats,
        "by_target_type": type_stats,
        "last_scan": last_scan,
    }


def backup_database(backup_path: Path) -> bool:
    """
    สำรองฐานข้อมูล
    
    Args:
        backup_path: ที่เก็บไฟล์สำรอง
    
    Returns:
        bool: True ถ้าสำเร็จ, False ถ้าไม่สำเร็จ
    """
    try:
        import shutil
        shutil.copy2(DB_PATH, backup_path)
        return True
    except Exception:
        return False


def restore_database(backup_path: Path) -> bool:
    """
    กู้คืนฐานข้อมูลจากไฟล์สำรอง
    
    Args:
        backup_path: ที่อยู่ของไฟล์สำรอง
    
    Returns:
        bool: True ถ้าสำเร็จ, False ถ้าไม่สำเร็จ
    """
    try:
        import shutil
        shutil.copy2(backup_path, DB_PATH)
        return True
    except Exception:
        return False