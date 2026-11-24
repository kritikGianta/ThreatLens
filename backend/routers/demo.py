"""Live demo control: background traffic and presenter-launched attack scenarios."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from dependencies.auth import get_current_user, require_writer
from models.database import get_db
from models.db_models import User
from services.audit import record_audit
from services.simulator import SCENARIOS, simulator

router = APIRouter()


class TrafficStart(BaseModel):
    rate: str = "normal"


@router.get("/status", dependencies=[Depends(get_current_user)])
def demo_status():
    return simulator.status()


@router.post("/traffic/start")
def start_traffic(request: Request, payload: TrafficStart, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    try:
        status = simulator.start_traffic(payload.rate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    record_audit(db, "demo.traffic_start", actor=user, details={"rate": payload.rate}, request=request, commit=True)
    return status


@router.post("/traffic/stop")
def stop_traffic(request: Request, db: Session = Depends(get_db), user: User = Depends(require_writer)):
    record_audit(db, "demo.traffic_stop", actor=user, request=request, commit=True)
    return simulator.stop_traffic()


@router.post("/scenarios/{scenario_id}/launch")
def launch_scenario(
    request: Request, scenario_id: str, speed: float = Query(1.0, ge=0.25, le=8.0),
    db: Session = Depends(get_db), user: User = Depends(require_writer),
):
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Unknown scenario '{scenario_id}'")
    try:
        scenario = simulator.launch(scenario_id, speed=speed, launched_by=user.username)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    record_audit(db, "demo.scenario_launch", actor=user, target_type="scenario", target_id=scenario_id,
                 details={"speed": speed, "attacker_ip": scenario["attacker_ip"]}, request=request, commit=True)
    return scenario


@router.post("/scenarios/stop", dependencies=[Depends(require_writer)])
def stop_scenario():
    return simulator.stop_scenario()
