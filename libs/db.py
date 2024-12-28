import sys
sys.path.append(".")
import sqlite3
from typing import Optional, Tuple

def get_data(db_name: str, SQL_request: str, params: Tuple = ()) -> Optional[str]:
    """Get data from database

    Args:
        db_name (str): Database name
        SQL_request (str): SQL request to execute for getting data
        params (tuple, optional): Parameters for SQL request

    Raises:
        Exception: Error in cursor.execute() or cursor.fetchone()

    Returns:
        Optional[str]: Data or None if no data found
    """
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(SQL_request, params)
            row = cursor.fetchone()
            return row[0] if row is not None else None
        except sqlite3.Error as error:
            raise Exception(f"Sqlite3.error: {error}")

def check_data(db_name: str, SQL_request: str, params: Tuple = ()) -> bool:
    """Check Data in Database

    Args:
        db_name (str): Database name
        SQL_request (str): SQL request to execute for checking data
        params (tuple, optional): Parameters for SQL request

    Raises:
        Exception: Error in cursor.execute() or cursor.fetchone()

    Returns:
        bool: True if data is found, False otherwise
    """
    data = get_data(db_name, SQL_request, params)
    return data is not None

def execute_SQL(db_name: str, SQL_request: str, params: Tuple = ()) -> None:
    """Execute custom SQL with commit()

    Args:
        db_name (str): Database name
        SQL_request (str): SQL request to execute
        params (tuple, optional): Parameters for SQL request

    Raises:
        Exception: Error in executing SQL request and committing changes
    """
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(SQL_request, params)
            conn.commit()
        except sqlite3.Error as error:
            raise Exception(f"Sqlite3.error: {error}")
