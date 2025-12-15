import os
import json
import pymysql
import requests
from datetime import date, datetime
from collections import defaultdict

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "trit")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "trit_dev")

ES_BASE_URL = os.getenv("ES_BASE_URL", "http://localhost:19200")
OUT_DIR = os.getenv("OUT_DIR", ".")


def to_iso(v):
    if v is None:
        return None
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v


def geo_point(lat, lng):
    if lat is None or lng is None:
        return None
    return {"lat": float(lat), "lon": float(lng)}


def get_conn():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def write_ndjson(path, actions_and_docs):
    with open(path, "w", encoding="utf-8") as f:
        for line in actions_and_docs:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")


def export_spots(conn):
    sql = """
    SELECT
      s.id,
      s.kakao_place_id,
      s.name,
      s.address,
      s.category,
      s.lat,
      s.lng,
      s.place_url,
      s.thumbnail_url,
      s.review_count,
      s.average_rating,
      s.created_at
    FROM spot s
    ORDER BY s.id
    """
    actions = []
    with conn.cursor() as cur:
        cur.execute(sql)
        for r in cur.fetchall():
            doc = {
                "spotId": r["id"],
                "kakaoPlaceId": r["kakao_place_id"],
                "name": r["name"],
                "address": r["address"],
                "category": r["category"],
                "location": geo_point(r["lat"], r["lng"]),
                "lat": float(r["lat"]) if r["lat"] is not None else None,
                "lng": float(r["lng"]) if r["lng"] is not None else None,
                "placeUrl": r["place_url"],
                "thumbnailUrl": r["thumbnail_url"],
                "reviewCount": r["review_count"] if r["review_count"] is not None else 0,
                "averageRating": float(r["average_rating"]) if r["average_rating"] is not None else 0.0,
                "createdAt": to_iso(r["created_at"]),
            }
            actions.append({"index": {"_index": "trit_spot", "_id": str(r["id"])}})
            actions.append(doc)
    return actions


def export_trips(conn):
    # trip + trip_status code + trip_item + spot
    sql = """
    SELECT
      t.id AS trip_id,
      t.user_id,
      ts.code AS status_code,
      t.visibility,
      t.title,
      t.start_date,
      t.end_date,
      t.created_at,
      t.updated_at,

      ti.day_number,
      ti.order_index,

      s.id AS spot_id,
      s.name AS spot_name,
      s.category AS spot_category,
      s.address AS spot_address,
      s.lat AS spot_lat,
      s.lng AS spot_lng
    FROM trip t
    JOIN trip_status ts ON ts.id = t.trip_status_id
    LEFT JOIN trip_item ti ON ti.trip_id = t.id
    LEFT JOIN spot s ON s.id = ti.spot_id
    ORDER BY t.id, ti.day_number, ti.order_index
    """

    trips = {}
    with conn.cursor() as cur:
        cur.execute(sql)
        for r in cur.fetchall():
            trip_id = r["trip_id"]
            if trip_id not in trips:
                trips[trip_id] = {
                    "tripId": trip_id,
                    "userId": r["user_id"],
                    "status": r["status_code"],
                    "visibility": r["visibility"],
                    "title": r["title"],
                    "startDate": to_iso(r["start_date"]),
                    "endDate": to_iso(r["end_date"]),
                    "createdAt": to_iso(r["created_at"]),
                    "updatedAt": to_iso(r["updated_at"]),
                    "spots": [],
                }

            if r["spot_id"] is not None:
                trips[trip_id]["spots"].append({
                    "spotId": r["spot_id"],
                    "name": r["spot_name"],
                    "category": r["spot_category"],
                    "address": r["spot_address"],
                    "location": geo_point(r["spot_lat"], r["spot_lng"]),
                    "dayNumber": r["day_number"],
                    "orderIndex": r["order_index"],
                })

    actions = []
    for trip_id, doc in trips.items():
        actions.append({"index": {"_index": "trit_trip", "_id": str(trip_id)}})
        actions.append(doc)
    return actions


def export_trip_logs(conn):
    # trip_log + (trip -> user_id) + spots(from trip_item/spot) + images(from log_image)
    sql_logs_spots = """
    SELECT
      tl.id AS log_id,
      tl.trip_id,
      t.user_id,
      tl.title AS log_title,
      tl.content AS log_content,
      tl.location_summary,
      tl.created_at AS log_created_at,
      tl.updated_at AS log_updated_at,

      s.id AS spot_id,
      s.name AS spot_name,
      s.category AS spot_category,
      s.address AS spot_address,
      s.lat AS spot_lat,
      s.lng AS spot_lng
    FROM trip_log tl
    JOIN trip t ON t.id = tl.trip_id
    LEFT JOIN trip_item ti ON ti.trip_id = tl.trip_id
    LEFT JOIN spot s ON s.id = ti.spot_id
    ORDER BY tl.id, ti.day_number, ti.order_index
    """

    logs = {}
    with conn.cursor() as cur:
        cur.execute(sql_logs_spots)
        for r in cur.fetchall():
            log_id = r["log_id"]
            if log_id not in logs:
                logs[log_id] = {
                    "logId": log_id,
                    "tripId": r["trip_id"],
                    "userId": r["user_id"],
                    "title": r["log_title"],
                    "content": r["log_content"],
                    "locationSummary": r["location_summary"],
                    "createdAt": to_iso(r["log_created_at"]),
                    "updatedAt": to_iso(r["log_updated_at"]),
                    "spots": [],
                    "images": [],
                }

            if r["spot_id"] is not None:
                logs[log_id]["spots"].append({
                    "spotId": r["spot_id"],
                    "name": r["spot_name"],
                    "category": r["spot_category"],
                    "address": r["spot_address"],
                    "location": geo_point(r["spot_lat"], r["spot_lng"]),
                })

    # images
    sql_images = """
    SELECT
      li.log_id,
      li.image_url,
      li.order_index,
      li.image_ref_key
    FROM log_image li
    WHERE li.log_id IS NOT NULL
    ORDER BY li.log_id, li.order_index
    """
    with conn.cursor() as cur:
        cur.execute(sql_images)
        for r in cur.fetchall():
            log_id = r["log_id"]
            if log_id in logs:
                logs[log_id]["images"].append({
                    "imageUrl": r["image_url"],
                    "orderIndex": r["order_index"],
                    "imageRefKey": r["image_ref_key"],
                })

    actions = []
    for log_id, doc in logs.items():
        actions.append({"index": {"_index": "trit_trip_log", "_id": str(log_id)}})
        actions.append(doc)
    return actions


def bulk_upload(ndjson_path, es_base_url):
    with open(ndjson_path, "rb") as f:
        resp = requests.post(
            f"{es_base_url}/_bulk?refresh=true",
            data=f,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=60,
        )
    resp.raise_for_status()
    result = resp.json()
    if result.get("errors"):
        # 에러 일부만 출력
        items = result.get("items", [])
        bad = [it for it in items if list(it.values())[0].get("error")]
        print(f"[WARN] bulk errors: {len(bad)} items failed")
        print(json.dumps(bad[:3], ensure_ascii=False, indent=2))
    else:
        print("[OK] bulk success")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    conn = get_conn()
    try:
        spot_actions = export_spots(conn)
        trip_actions = export_trips(conn)
        log_actions = export_trip_logs(conn)
    finally:
        conn.close()

    spot_file = os.path.join(OUT_DIR, "trit_spot.ndjson")
    trip_file = os.path.join(OUT_DIR, "trit_trip.ndjson")
    log_file = os.path.join(OUT_DIR, "trit_trip_log.ndjson")

    write_ndjson(spot_file, spot_actions)
    write_ndjson(trip_file, trip_actions)
    write_ndjson(log_file, log_actions)

    print(f"wrote: {spot_file}")
    print(f"wrote: {trip_file}")
    print(f"wrote: {log_file}")

    if os.getenv("BULK_UPLOAD", "false").lower() == "true":
        bulk_upload(spot_file, ES_BASE_URL)
        bulk_upload(trip_file, ES_BASE_URL)
        bulk_upload(log_file, ES_BASE_URL)


if __name__ == "__main__":
    main()
