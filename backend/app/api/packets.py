import csv
import io
import os
import uuid
import shutil
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, delete

from app.database.database import get_db
from app.core.permissions import get_current_user
from app.schemas.users import User
from app.database.models import LogEvent
from app.threat_intel.service import ThreatIntelService
from app.services.packet_service import (
    analyze_pcap_file,
    generate_synthetic_demo_pcap,
    get_available_interfaces,
    generate_live_packet,
    CAPTURES_DIR,
    MAX_UPLOAD_SIZE,
)

router = APIRouter()
threat_intel_service = ThreatIntelService()

# Cache parsed captures in memory for high-performance navigation
PARSED_CAPTURES_CACHE: Dict[str, Dict[str, Any]] = {}
CAPTURES_METADATA_LIST: List[Dict[str, Any]] = []

DEMO_FILE_PATH = os.path.join(CAPTURES_DIR, "demo_security.pcap")


# ─── Live Capture Endpoints (#38, #39, #40) ──────────────────────────────────

@router.get("/interfaces")
async def list_interfaces(current_user: User = Depends(get_current_user)):
    """Returns host network interfaces detected for live capture."""
    return get_available_interfaces()


@router.get("/live-packet")
async def get_live_packet(
    counter: int = Query(1),
    base_time: float = Query(0.0),
    iface: str = Query("eth0"),
    current_user: User = Depends(get_current_user)
):
    """
    Returns a newly captured dissected packet record with real protocol structures,
    hex dump, and OSI layers.
    """
    return generate_live_packet(counter, base_time, iface)


# ─── PCAP Upload & Analysis Endpoints ─────────────────────────────────────────

@router.post("/upload")
async def upload_pcap(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Securely uploads and analyzes a PCAP / PCAPNG file.
    Validates file extension, size, and parses protocol layers,
    conversations, endpoints, and security indicators.
    """
    filename = os.path.basename(file.filename or "capture.pcap")
    ext = os.path.splitext(filename)[1].lower()

    if ext not in [".pcap", ".pcapng", ".cap"]:
        raise HTTPException(
            status_code=400,
            detail="Unsupported capture format. Please upload a .pcap or .pcapng file."
        )

    # Sanitize and assign unique storage path
    capture_id = f"cap-{uuid.uuid4().hex[:12]}"
    safe_filename = f"{capture_id}_{filename}"
    target_path = os.path.join(CAPTURES_DIR, safe_filename)

    try:
        # Write file with size guard
        size = 0
        with open(target_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):  # 1MB chunks
                size += len(chunk)
                if size > MAX_UPLOAD_SIZE:
                    buffer.close()
                    if os.path.exists(target_path):
                        os.remove(target_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"PCAP file exceeds maximum permitted size of {MAX_UPLOAD_SIZE // (1024*1024)}MB."
                    )
                buffer.write(chunk)

        # Analyze capture
        analysis = analyze_pcap_file(target_path)
        analysis["metadata"]["id"] = capture_id
        analysis["metadata"]["filename"] = filename
        analysis["metadata"]["analyzed_at"] = datetime.now(timezone.utc).isoformat()

        # Cache in memory
        PARSED_CAPTURES_CACHE[capture_id] = analysis

        # Add to captures list (keep recent 10)
        CAPTURES_METADATA_LIST.insert(0, {
            "id": capture_id,
            "filename": filename,
            "file_size": size,
            "packets": analysis["metadata"]["total_packets"],
            "analyzed_at": analysis["metadata"]["analyzed_at"],
            "duration": analysis["metadata"]["duration_formatted"]
        })
        if len(CAPTURES_METADATA_LIST) > 10:
            CAPTURES_METADATA_LIST.pop()

        return analysis

    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(target_path):
            try:
                os.remove(target_path)
            except Exception:
                pass
        raise HTTPException(
            status_code=400,
            detail=f"Unable to analyze capture: The file may be corrupted or contains unrecognized packet structures. Details: {str(e)}"
        )


@router.get("/demo")
async def get_demo_capture(current_user: User = Depends(get_current_user)):
    """
    Returns the synthetic demonstration PCAP analysis.
    Auto-generates demo_security.pcap if not already present.
    """
    demo_id = "cap-demo-security"

    if demo_id in PARSED_CAPTURES_CACHE:
        return PARSED_CAPTURES_CACHE[demo_id]

    if not os.path.exists(DEMO_FILE_PATH):
        generate_synthetic_demo_pcap(DEMO_FILE_PATH)

    analysis = analyze_pcap_file(DEMO_FILE_PATH)
    analysis["metadata"]["id"] = demo_id
    analysis["metadata"]["filename"] = "demo_security.pcap"
    analysis["metadata"]["analyzed_at"] = datetime.now(timezone.utc).isoformat()

    PARSED_CAPTURES_CACHE[demo_id] = analysis

    # Register in metadata list if not present
    if not any(c["id"] == demo_id for c in CAPTURES_METADATA_LIST):
        CAPTURES_METADATA_LIST.append({
            "id": demo_id,
            "filename": "demo_security.pcap",
            "file_size": os.path.getsize(DEMO_FILE_PATH),
            "packets": analysis["metadata"]["total_packets"],
            "analyzed_at": analysis["metadata"]["analyzed_at"],
            "duration": analysis["metadata"]["duration_formatted"]
        })

    return analysis


@router.get("/captures")
async def list_captures(current_user: User = Depends(get_current_user)):
    """Returns list of recent analyzed captures."""
    # Ensure demo is always available
    if not any(c["id"] == "cap-demo-security" for c in CAPTURES_METADATA_LIST):
        CAPTURES_METADATA_LIST.append({
            "id": "cap-demo-security",
            "filename": "demo_security.pcap",
            "file_size": 3748,
            "packets": 45,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "duration": "00:06"
        })
    return CAPTURES_METADATA_LIST


@router.get("/captures/{capture_id}")
async def get_capture(capture_id: str, current_user: User = Depends(get_current_user)):
    """Returns the full analysis data for a specific capture ID."""
    if capture_id == "cap-demo-security":
        return await get_demo_capture(current_user)

    if capture_id not in PARSED_CAPTURES_CACHE:
        raise HTTPException(status_code=404, detail="Capture analysis expired or not found.")

    return PARSED_CAPTURES_CACHE[capture_id]


# ─── Threat Intelligence for IP Investigation (#23, #24) ──────────────────────

@router.get("/ip-reputation/{ip}")
async def get_ip_reputation(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Checks IP reputation through the application's Threat Intelligence engine.
    Gracefully handles internal/loopback IPs.
    """
    try:
        rep = await threat_intel_service.get_ip_reputation(db, ip)
        return rep
    except Exception as e:
        return {
            "ip": ip,
            "provider": "local",
            "status": "UNAVAILABLE",
            "message": "Threat intelligence lookup temporarily unavailable"
        }


# ─── CSV Export (#29) ────────────────────────────────────────────────────────

class ExportPacketItem(BaseModel):
    no: int
    time_str: Optional[str] = None
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

class ExportRequest(BaseModel):
    filename: Optional[str] = "packet_analysis_export.csv"
    packets: List[ExportPacketItem]


@router.post("/export")
async def export_packets_csv(
    req: ExportRequest,
    current_user: User = Depends(get_current_user)
):
    """Exports analyzed/filtered packets to a downloadable CSV file."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "No.", "Time", "Source IP", "Destination IP",
        "Source Port", "Destination Port", "Protocol", "Length", "Info"
    ])

    for pkt in req.packets:
        writer.writerow([
            pkt.no,
            pkt.time_str or "",
            pkt.source,
            pkt.destination,
            pkt.source_port or "",
            pkt.destination_port or "",
            pkt.protocol,
            pkt.length,
            pkt.info
        ])

    output.seek(0)
    filename = req.filename if req.filename.endswith(".csv") else f"{req.filename}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ─── Backwards Compatibility Endpoints (Database LogEvents) ──────────────────

class PacketRow(BaseModel):
    event_time: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    length: Optional[int] = None
    severity: Optional[str] = None
    service: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    host: Optional[str] = None
    action: Optional[str] = None
    message: Optional[str] = None
    event_type: Optional[str] = None
    raw_message: Optional[str] = None

class SyncRequest(BaseModel):
    packets: List[PacketRow]
    append: bool = False

CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "packet_capture.csv")

@router.get("/")
async def get_packets(
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Return log events for the Packet Analyzer UI (database view)."""
    query = select(LogEvent).order_by(LogEvent.event_time.asc()).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()
    packets = []
    for i, ev in enumerate(events):
        packets.append({
            "no": i + 1,
            "time": ev.event_time.isoformat() if ev.event_time else None,
            "source": ev.source_ip or "N/A",
            "destination": ev.destination_ip or "N/A",
            "protocol": ev.protocol or "TCP",
            "length": 54 + len(ev.raw_message or ev.message or ""),
            "info": ev.message or "",
            "source_port": ev.source_port,
            "destination_port": ev.destination_port,
            "host": ev.host,
            "service": ev.service,
            "severity": ev.severity,
        })
    return packets

@router.post("/sync")
async def sync_packets(
    req: SyncRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Receives packet data and persists to CSV and database."""
    if not req.append:
        await db.execute(delete(LogEvent).where(LogEvent.parser_name == "packet_analyzer"))
        await db.commit()

    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    csv_fields = [
        "no", "event_time", "source_ip", "destination_ip", "source_port",
        "destination_port", "protocol", "length", "severity", "service",
        "method", "path", "status_code", "host", "action", "message",
        "event_type", "raw_message"
    ]
    file_exists = os.path.exists(CSV_PATH) and os.path.getsize(CSV_PATH) > 0
    with open(CSV_PATH, "a" if req.append else "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        if not req.append or not file_exists:
            writer.writeheader()
        for i, pkt in enumerate(req.packets):
            row = pkt.model_dump()
            row["no"] = i + 1
            writer.writerow(row)

    now = datetime.now(timezone.utc)
    inserted = 0
    for pkt in req.packets:
        try:
            event_time = pkt.event_time
            if len(event_time) == 16:
                event_time += ":00"
            ev = LogEvent(
                event_time=event_time,
                ingested_at=now,
                host=pkt.host,
                source_ip=pkt.source_ip,
                destination_ip=pkt.destination_ip,
                source_port=pkt.source_port,
                destination_port=pkt.destination_port,
                event_type=pkt.event_type,
                action=pkt.action,
                protocol=pkt.protocol,
                service=pkt.service,
                method=pkt.method,
                path=pkt.path,
                status_code=pkt.status_code,
                severity=pkt.severity,
                message=pkt.message,
                raw_message=pkt.raw_message,
                parser_name="packet_analyzer",
                parse_status="PARSED",
            )
            db.add(ev)
            inserted += 1
        except Exception:
            pass

    await db.commit()
    return {"status": "ok", "packets_written": len(req.packets), "db_inserted": inserted}
