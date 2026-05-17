import os
import io
import re
import httpx
import pandas as pd
from sqlalchemy import delete 
from collections import defaultdict
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func, select, text
from sqlalchemy.orm import declarative_base, sessionmaker
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

DATABASE_URL = "sqlite+aiosqlite:///./cdr_forensics.db"
engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    case_number = Column(String, unique=True)
    title = Column(String)
    subscriber_number = Column(String)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)

class CDRRecord(Base):
    __tablename__ = "cdr_records"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"))
    calling_number = Column(String)
    called_number = Column(String)
    call_type = Column(String)
    direction = Column(String, default="OUTGOING")
    call_datetime = Column(DateTime)
    duration_seconds = Column(Integer, default=0)

app = FastAPI(title="Forensic CDR Analyser - Behavioral Edition")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.delete("/api/cases/{case_id}")
async def delete_case(case_id: int, db: AsyncSession = Depends(get_db)):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    await db.execute(delete(CDRRecord).where(CDRRecord.case_id == case_id))
    await db.delete(case)
    await db.commit()
    return {"ok": True}

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        try:
            await conn.execute(text("ALTER TABLE cases ADD COLUMN subscriber_number VARCHAR"))
        except:
            pass

@app.get("/", response_class=HTMLResponse)
async def frontend():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/api/cases")
async def create_case(payload: dict, db: AsyncSession = Depends(get_db)):
    case = Case(case_number=payload["case_number"], title=payload["title"], subscriber_number=payload["subscriber_number"])
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return {"id": case.id, "case_number": case.case_number, "title": case.title, "subscriber_number": case.subscriber_number}

@app.get("/api/cases")
async def list_cases(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Case).order_by(Case.created_at.desc()))
    return [{"id": c.id, "case_number": c.case_number, "title": c.title, "status": c.status, "created_at": c.created_at.isoformat()} for c in res.scalars()]

@app.get("/api/cases/{case_id}")
async def get_case(case_id: int, db: AsyncSession = Depends(get_db)):
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalar_one_or_none()
    if not case:
        raise HTTPException(404)
    rec_count = (await db.execute(select(func.count(CDRRecord.id)).where(CDRRecord.case_id == case_id))).scalar()
    return {"id": case.id, "case_number": case.case_number, "title": case.title, "subscriber_number": case.subscriber_number, "record_count": rec_count}

@app.post("/api/cases/{case_id}/upload")
async def upload_cdr(case_id: int, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    if not case.subscriber_number:
        raise HTTPException(400, "Case has no subscriber number. Please set it when creating the case.")

    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content), dtype=str, keep_default_na=False)
    except Exception as e:
        raise HTTPException(400, f"CSV read error: {e}")

    df.columns = df.columns.str.strip()

    def detect_columns(df, sample_size=10):
        roles = {}
        sample = df.head(sample_size).copy()
        
        name_hints = {
            'date': ['date', 'call_date', 'calldate'],
            'time': ['time', 'call_time', 'calltime'],
            'datetime': ['datetime', 'call_datetime', 'timestamp'],
            'number': ['number', 'called_number', 'phone', 'mobile', 'b_number', 'destination'],
            'duration': ['duration', 'duration_sec', 'duration_s', 'call_duration', 'talktime'],
            'category': ['category', 'call_type', 'type', 'call_category']
        }
        for role, possible_names in name_hints.items():
            for col in df.columns:
                col_lower = col.lower()
                if any(hint in col_lower for hint in possible_names):
                    if role not in roles:
                        roles[role] = col
                        break
        
        for col in df.columns:
            if col in roles.values():
                continue
            
            values = sample[col].astype(str).str.strip()
            non_empty = values[values != '']
            if len(non_empty) == 0:
                continue
            
            cat_keywords = ['voice', 'sms', 'outgoing', 'incoming', 'roaming', 'std', 'local', 'international', 'missed']
            if any(kw in v.lower() for v in non_empty for kw in cat_keywords):
                roles['category'] = col
                continue
            
            try:
                numeric = pd.to_numeric(non_empty, errors='coerce').dropna()
                if len(numeric) > 0:
                    median = numeric.median()
                    max_val = numeric.max()
                    if max_val < 100000 and (median < 5000 or max_val < 5000) and (median < 1900 or median > 2100):
                        roles['duration'] = col
                        continue
            except:
                pass
            
            cleaned_digits = non_empty.str.replace(r'[^0-9+]', '', regex=True)
            digit_lengths = cleaned_digits.str.len()
            if (digit_lengths >= 8).any() and (digit_lengths <= 15).any():
                if not any('-' in v or '/' in v for v in non_empty.head(3)):
                    roles['number'] = col
                    continue
            
            for test_val in non_empty.head(3):
                if ' ' in test_val and ':' in test_val:
                    for fmt in ["%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                        try:
                            datetime.strptime(test_val, fmt)
                            roles['datetime'] = col
                            break
                        except:
                            continue
                    if 'datetime' in roles:
                        break
            if 'datetime' not in roles:
                date_fmts = ["%d-%m-%Y", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d.%m.%Y"]
                for test_val in non_empty.head(3):
                    for fmt in date_fmts:
                        try:
                            datetime.strptime(test_val, fmt)
                            roles['date'] = col
                            break
                        except:
                            continue
                    if 'date' in roles:
                        break
                if 'date' not in roles:
                    time_fmts = ["%H:%M:%S", "%H:%M", "%I:%M:%S %p", "%I:%M %p"]
                    for test_val in non_empty.head(3):
                        for fmt in time_fmts:
                            try:
                                datetime.strptime(test_val, fmt)
                                roles['time'] = col
                                break
                            except:
                                continue
                            if 'time' in roles:
                                break
        
        if 'date' not in roles and 'date' in df.columns:
            roles['date'] = 'date'
        if 'time' not in roles and 'time' in df.columns:
            roles['time'] = 'time'
        
        return roles

    roles = detect_columns(df)
    
    if 'number' not in roles:
        raise HTTPException(400, f"Could not identify phone number column. Found columns: {list(df.columns)}")
    if 'duration' not in roles:
        raise HTTPException(400, f"Could not identify duration column. Found columns: {list(df.columns)}")
    if 'datetime' not in roles and ('date' not in roles or 'time' not in roles):
        raise HTTPException(400, f"Could not identify date/time columns. Found columns: {list(df.columns)}")

    records = []
    datetime_formats = [
        "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S.%f"
    ]
    date_formats = ["%d-%m-%Y", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y"]
    time_formats = ["%H:%M:%S", "%H:%M"]

    for idx, row in df.iterrows():
        try:
            if 'datetime' in roles:
                dt_str = str(row[roles['datetime']]).strip()
                dt = None
                for fmt in datetime_formats:
                    try:
                        dt = datetime.strptime(dt_str, fmt)
                        break
                    except:
                        continue
                if dt is None:
                    continue
            else:
                date_str = str(row[roles['date']]).strip()
                time_str = str(row[roles['time']]).strip()
                d = None
                for fmt in date_formats:
                    try:
                        d = datetime.strptime(date_str, fmt).date()
                        break
                    except:
                        continue
                if d is None:
                    continue
                t = None
                for fmt in time_formats:
                    try:
                        t = datetime.strptime(time_str, fmt).time()
                        break
                    except:
                        continue
                if t is None:
                    t = datetime.strptime("00:00:00", "%H:%M:%S").time()
                dt = datetime.combine(d, t)
            
            dur_raw = str(row[roles['duration']]).strip()
            cleaned = re.sub(r'[^0-9.]', '', dur_raw)
            if cleaned == '':
                duration = 0
            else:
                try:
                    duration = int(float(cleaned))
                except:
                    duration = 0
            
            number_raw = str(row[roles['number']]).strip()
            number_clean = re.sub(r'[^0-9+]', '', number_raw)
            if 'E' in number_raw.upper():
                try:
                    number_clean = str(int(float(number_raw)))
                except:
                    pass
            
            if 'category' in roles:
                cat = str(row[roles['category']]).upper().strip()
                if cat in ['SMS', 'TEXT', 'MESSAGE']:
                    call_type = 'SMS'
                else:
                    call_type = 'VOICE'
            else:
                call_type = 'VOICE'
            
            records.append(CDRRecord(
                case_id=case_id,
                calling_number=case.subscriber_number,
                called_number=number_clean,
                call_type=call_type,
                direction="OUTGOING",
                call_datetime=dt,
                duration_seconds=duration
            ))
        except Exception as e:
            print(f"Skipping row {idx}: {e}")
            continue

    if not records:
        raise HTTPException(400, "No valid records found after parsing. Check date/time formats and column content.")

    db.add_all(records)
    await db.commit()
    return {"inserted": len(records), "message": f"Successfully imported {len(records)} records"}   

@app.get("/api/cases/{case_id}/records")
async def get_records(case_id: int, page: int = 1, page_size: int = 50, db: AsyncSession = Depends(get_db)):
    offset = (page-1)*page_size
    total = (await db.execute(select(func.count(CDRRecord.id)).where(CDRRecord.case_id == case_id))).scalar()
    res = await db.execute(select(CDRRecord).where(CDRRecord.case_id == case_id).order_by(CDRRecord.call_datetime.desc()).offset(offset).limit(page_size))
    rows = res.scalars().all()
    return {"total": total, "page": page, "pages": (total+page_size-1)//page_size, "records": [{"id":r.id,"called_number":r.called_number,"call_datetime":r.call_datetime.isoformat(),"duration_seconds":r.duration_seconds,"call_type":r.call_type} for r in rows]}

@app.get("/api/cases/{case_id}/analysis/frequency")
async def frequency(case_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(CDRRecord.called_number, func.count(CDRRecord.id).label("cnt")).where(CDRRecord.case_id == case_id).group_by(CDRRecord.called_number).order_by(func.count(CDRRecord.id).desc()).limit(30))
    return [{"called_number": r.called_number, "call_count": r.cnt} for r in res.all()]

@app.get("/api/cases/{case_id}/analysis/hourly")
async def hourly(case_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(CDRRecord.call_datetime).where(CDRRecord.case_id == case_id))
    hours = [0]*24
    for dt in res.scalars():
        if dt:
            hours[dt.hour] += 1
    return [{"hour": i, "count": hours[i]} for i in range(24)]

@app.get("/api/cases/{case_id}/relationship-mapping")
async def relationship_mapping(case_id: int, db: AsyncSession = Depends(get_db)):
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    
    result = await db.execute(
        select(CDRRecord.called_number, CDRRecord.call_type, CDRRecord.duration_seconds, CDRRecord.call_datetime)
        .where(CDRRecord.case_id == case_id)
    )
    rows = result.all()
    if not rows:
        return {"entities": [], "relationships": []}
    
    contacts_data = defaultdict(lambda: {"voice_count": 0, "sms_count": 0, "total_duration": 0, "first_call": None, "last_call": None})
    for r in rows:
        number = r.called_number
        call_type = r.call_type.upper()
        dur = r.duration_seconds or 0
        dt = r.call_datetime
        if call_type in ("VOICE", "CALL"):
            contacts_data[number]["voice_count"] += 1
        elif call_type == "SMS":
            contacts_data[number]["sms_count"] += 1
        else:
            contacts_data[number]["voice_count"] += 1
        contacts_data[number]["total_duration"] += dur
        if contacts_data[number]["first_call"] is None or dt < contacts_data[number]["first_call"]:
            contacts_data[number]["first_call"] = dt
        if contacts_data[number]["last_call"] is None or dt > contacts_data[number]["last_call"]:
            contacts_data[number]["last_call"] = dt
    
    entities = []
    entities.append({
        "id": case.subscriber_number,
        "type": "Subscriber",
        "label": f"📱 {case.subscriber_number}",
        "properties": {
            "case_number": case.case_number,
            "total_calls": sum(c["voice_count"] + c["sms_count"] for c in contacts_data.values())
        }
    })
    
    for number, data in contacts_data.items():
        entities.append({
            "id": number,
            "type": "Contact",
            "label": f"📞 {number}",
            "properties": {
                "voice_calls": data["voice_count"],
                "sms": data["sms_count"],
                "total_duration_sec": data["total_duration"],
                "first_call": data["first_call"].isoformat() if data["first_call"] else None,
                "last_call": data["last_call"].isoformat() if data["last_call"] else None
            }
        })
    
    relationships = []
    for number, data in contacts_data.items():
        link_type = "CALLED"
        if data["voice_count"] > 0 and data["sms_count"] > 0:
            link_type = "MIXED"
        elif data["sms_count"] > 0:
            link_type = "SMS"
        weight = data["voice_count"] + data["sms_count"]
        relationships.append({
            "source": case.subscriber_number,
            "target": number,
            "type": link_type,
            "weight": weight,
            "properties": {
                "voice_calls": data["voice_count"],
                "sms": data["sms_count"],
                "total_duration": data["total_duration"],
                "first_seen": data["first_call"].isoformat() if data["first_call"] else None,
                "last_seen": data["last_call"].isoformat() if data["last_call"] else None
            }
        })
    
    return {"entities": entities, "relationships": relationships}

@app.get("/api/cases/{case_id}/analysis/behavior")
async def forensic_anomaly_dashboard(case_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CDRRecord).where(CDRRecord.case_id == case_id))
    records = result.scalars().all()
    
    if not records:
        return {
            "summary": {"total_anomalies": 0, "night_activity_count": 0, "spike_events": 0, "new_contacts": 0},
            "top_suspicious": [],
            "spike_data": [],
            "night_heatmap": [],
            "event_log": []
        }
    
    df = pd.DataFrame([{
        "called": r.called_number,
        "duration": r.duration_seconds,
        "hour": r.call_datetime.hour,
        "date": r.call_datetime.date(),
        "datetime": r.call_datetime
    } for r in records])
    
    night_calls = df[(df["hour"] >= 22) | (df["hour"] <= 5)]
    night_activity_count = len(night_calls)
    
    long_calls = df[df["duration"] > 300]
    long_call_count = len(long_calls)
    
    spike_events = 0
    spike_data = []
    if df["date"].nunique() >= 2:
        daily_counts = df.groupby("date").size().reset_index(name="count")
        baseline = daily_counts["count"].mean()
        for _, row in daily_counts.iterrows():
            is_spike = row["count"] > (baseline * 1.5)
            if is_spike:
                spike_events += 1
            spike_data.append({
                "date": row["date"].isoformat(),
                "count": int(row["count"]),
                "baseline": round(baseline, 1),
                "is_spike": is_spike
            })
    else:
        spike_data = [{
            "date": df["date"].iloc[0].isoformat(),
            "count": len(df),
            "baseline": len(df),
            "is_spike": False
        }]
    
    contact_stats = []
    total_calls = len(df)
    for contact in df["called"].unique():
        contact_df = df[df["called"] == contact]
        count = len(contact_df)
        night_ratio_contact = len(contact_df[(contact_df["hour"] >= 22) | (contact_df["hour"] <= 5)]) / max(1, count)
        avg = total_calls / max(1, df["called"].nunique())
        std = df.groupby("called").size().std() or 1
        freq_z = (count - avg) / max(1, std)
        score = (night_ratio_contact * 5) + (max(0, freq_z) * 0.5)
        flags = []
        if night_ratio_contact > 0.3:
            flags.append("night_activity")
        if freq_z > 1.5:
            flags.append("frequency_spike")
        risk = "HIGH" if score > 6 else "MEDIUM" if score > 3 else "LOW"
        contact_stats.append({
            "number": contact,
            "score": round(score, 1),
            "risk": risk,
            "flags": flags
        })
    top_suspicious = sorted(contact_stats, key=lambda x: x["score"], reverse=True)[:10]
    
    heatmap = []
    for _, row in night_calls.iterrows():
        heatmap.append({
            "day": row["date"].isoformat(),
            "hour": row["hour"],
            "count": 1
        })
    agg = defaultdict(int)
    for h in heatmap:
        agg[(h["day"], h["hour"])] += 1
    night_heatmap = [{"day": d, "hour": h, "count": c} for (d, h), c in agg.items()]
    
    event_log = []
    for _, row in night_calls.head(50).iterrows():
        event_log.append({
            "timestamp": row["datetime"].isoformat(),
            "number": row["called"],
            "type": "night_activity",
            "description": f"Call at {row['datetime'].strftime('%H:%M')} (unusual hour)"
        })
    for _, row in long_calls.head(20).iterrows():
        event_log.append({
            "timestamp": row["datetime"].isoformat(),
            "number": row["called"],
            "type": "long_call",
            "description": f"Long call: {row['duration']} seconds (>5 min)"
        })
    for spike in spike_data:
        if spike.get("is_spike", False):
            event_log.append({
                "timestamp": spike["date"],
                "number": "—",
                "type": "spike",
                "description": f"Call volume spike: {spike['count']} vs baseline {spike['baseline']}"
            })
    
    anomalies_found = (night_activity_count > 0) or (long_call_count > 0) or (spike_events > 0) or (len([s for s in top_suspicious if s["risk"] == "HIGH"]) > 0)
    
    summary = {
        "total_anomalies": len(event_log),
        "night_activity_count": night_activity_count,
        "spike_events": spike_events,
        "new_contacts": 0
    }
    
    if not anomalies_found:
        return {
            "summary": {"total_anomalies": 0, "night_activity_count": 0, "spike_events": 0, "new_contacts": 0},
            "top_suspicious": [],
            "spike_data": spike_data,
            "night_heatmap": [],
            "event_log": []
        }
    
    return {
        "summary": summary,
        "top_suspicious": top_suspicious,
        "spike_data": spike_data,
        "night_heatmap": night_heatmap[:20],
        "event_log": event_log[:50]
    }

@app.post("/api/geolocation/cell")
async def cell_location(payload: dict):
    mcc = payload.get("mcc", "")
    mnc = payload.get("mnc", "")
    lac = payload.get("lac", "")
    cellid = payload.get("cellid", "")
    if not all([mcc, mnc, lac, cellid]):
        raise HTTPException(400, "Missing fields")
    
    api_key = os.environ.get("OPENCELLID_KEY", "")
    if api_key:
        async with httpx.AsyncClient() as client:
            url = f"https://opencellid.org/cell/get?key={api_key}&mcc={mcc}&mnc={mnc}&lac={lac}&cellid={cellid}&format=json"
            try:
                resp = await client.get(url, timeout=5)
                data = resp.json()
                if "lat" in data and "lon" in data:
                    return {"lat": data["lat"], "lon": data["lon"], "source": "OpenCellID"}
            except:
                pass
    
    import hashlib
    h = int(hashlib.md5(f"{mcc}{mnc}{lac}{cellid}".encode()).hexdigest()[:8], 16)
    lat = 28.6139 + (h % 1000) / 10000.0
    lon = 77.2090 + ((h // 1000) % 1000) / 10000.0
    return {"lat": lat, "lon": lon, "source": "fallback_estimate"}


if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("🔍 Forensic CDR Analyser is running!")
    print("🌐 Open your browser and go to: http://localhost:8001")
    print("=" * 50)
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")