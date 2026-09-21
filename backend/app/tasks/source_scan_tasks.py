import logging
import shutil
from datetime import datetime
from pathlib import Path
import traceback

from app.tasks.celery_app import celery_app
from app.tasks.scan_tasks import get_sync_session, emit_progress, run_async

from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.models.cbom import CBOMRecord

from app.core.source_scanner import ScanTarget
from app.core.source_scanner.python_scanner import PythonScanner
from app.core.container_scanner import ContainerScanner
from app.core.binary_scanner import BinaryScanner
from app.core.cbom.builder import build_cbom, cbom_to_json_string
from app.core.github.repository_fetcher import GitHubRepositoryFetcher

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="app.tasks.source_scan_tasks.run_source_scan")
def run_source_scan(self, scan_id: str, target: str, scan_depth: str, branch: str = None, token: str = None, repository: str = None):
    session = get_sync_session()
    temp_dir = None
    try:
        scan = session.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            logger.error(f"Scan job {scan_id} not found")
            return
        
        scan.status = "running"
        session.commit()
        
        emit_progress(scan_id, 'scan_start', 5, 'Initializing scan...')
        
        target_str = target
        is_git_url = (
            target_str.startswith(("http://", "https://", "git@"))
            or target_str.endswith(".git")
            or "github.com" in target_str
        )
        if not is_git_url and not Path(target_str).exists() and "/" in target_str and not target_str.startswith((".", "/")):
            is_git_url = True
            
        scan_path = target_str
        repo_name = repository

        if is_git_url:
            emit_progress(scan_id, 'fetch_repo', 15, 'Fetching repository...')
            logger.info("Fetching remote Git/GitHub repository: %s", target_str)
            try:
                temp_dir, detected_name, _ = run_async(GitHubRepositoryFetcher.fetch_codebase(
                    target=target_str,
                    branch=branch,
                    token=token,
                ))
                scan_path = temp_dir
                if not repo_name:
                    repo_name = detected_name
            except Exception as e:
                logger.error("Failed to fetch repository codebase: %s", e)
                raise Exception(f"Failed to fetch repository codebase from GitHub: {e}")
        else:
            resolved_path = Path(target_str).resolve()
            if not resolved_path.exists():
                raise Exception(f"Local path does not exist: {target_str}")
            scan_path = str(resolved_path)
            if not repo_name:
                repo_name = Path(target_str).name
                
        emit_progress(scan_id, 'scanning', 30, 'Scanning source code...')
        scanner = PythonScanner()
        scan_target = ScanTarget(
            path=scan_path,
            scan_type="source",
            language="python",
            depth=scan_depth,
            repository=repo_name,
        )
        scan_result = scanner.scan(scan_target)
        
        emit_progress(scan_id, 'saving_findings', 70, 'Saving findings...')
        created_assets = []
        qs_count = 0
        hybrid_count = 0
        vuln_count = 0

        for f in scan_result.findings:
            orm_kwargs = f.to_orm_kwargs()
            if temp_dir and orm_kwargs.get("file_path"):
                rel_path = str(Path(orm_kwargs["file_path"]).relative_to(Path(temp_dir)))
                orm_kwargs["file_path"] = rel_path
                if orm_kwargs.get("source_location"):
                    orm_kwargs["source_location"] = rel_path

            crypto_asset = CryptoAsset(
                scan_id=scan.id,
                **orm_kwargs,
            )
            session.add(crypto_asset)
            created_assets.append(crypto_asset)

            pqc = (f.pqc_status or "").upper()
            if pqc == "QUANTUM_SAFE":
                qs_count += 1
            elif pqc == "HYBRID_READY":
                hybrid_count += 1
            elif pqc == "VULNERABLE":
                vuln_count += 1
            else:
                vuln_count += 1

        emit_progress(scan_id, 'building_cbom', 90, 'Building CBOM...')
        cbom = build_cbom(
            scan_id=str(scan.id),
            target=target_str,
            assets=scan_result.findings,
        )
        cbom_json = cbom_to_json_string(cbom)
        cbom_record = CBOMRecord(
            scan_id=scan.id,
            cyclonedx_json=cbom_json,
        )
        session.add(cbom_record)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_assets = len(created_assets)
        scan.quantum_safe_count = qs_count
        scan.hybrid_count = hybrid_count
        scan.vulnerable_count = vuln_count

        session.commit()
        emit_progress(scan_id, 'complete', 100, 'Scan completed')

    except Exception as exc:
        logger.exception("Error executing source scan: %s", exc)
        try:
            scan = session.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(exc)
                scan.completed_at = datetime.utcnow()
                session.commit()
        except Exception:
            pass
        emit_progress(scan_id, 'error', -1, f"Scan failed: {str(exc)}")
    finally:
        session.close()
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

@celery_app.task(bind=True, name="app.tasks.source_scan_tasks.run_container_scan")
def run_container_scan(self, scan_id: str, target: str, scan_depth: str, repository: str = None):
    session = get_sync_session()
    try:
        scan = session.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            logger.error(f"Scan job {scan_id} not found")
            return
        
        scan.status = "running"
        session.commit()
        
        emit_progress(scan_id, 'scan_start', 5, 'Initializing scan...')
        
        emit_progress(scan_id, 'scanning', 30, 'Scanning container image...')
        scanner = ContainerScanner()
        scan_target = ScanTarget(
            path=target,
            scan_type="container",
            depth=scan_depth,
            repository=repository,
        )
        scan_result = scanner.scan(scan_target)

        emit_progress(scan_id, 'saving_findings', 70, 'Saving findings...')
        created_assets = []
        qs_count = 0
        hybrid_count = 0
        vuln_count = 0

        for f in scan_result.findings:
            orm_kwargs = f.to_orm_kwargs()
            crypto_asset = CryptoAsset(
                scan_id=scan.id,
                **orm_kwargs,
            )
            session.add(crypto_asset)
            created_assets.append(crypto_asset)

            pqc = (f.pqc_status or "").upper()
            if pqc == "QUANTUM_SAFE":
                qs_count += 1
            elif pqc == "HYBRID_READY":
                hybrid_count += 1
            elif pqc == "VULNERABLE":
                vuln_count += 1
            else:
                vuln_count += 1

        emit_progress(scan_id, 'building_cbom', 90, 'Building CBOM...')
        cbom = build_cbom(
            scan_id=str(scan.id),
            target=target,
            assets=scan_result.findings,
        )
        cbom_json = cbom_to_json_string(cbom)
        cbom_record = CBOMRecord(
            scan_id=scan.id,
            cyclonedx_json=cbom_json,
        )
        session.add(cbom_record)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_assets = len(created_assets)
        scan.quantum_safe_count = qs_count
        scan.hybrid_count = hybrid_count
        scan.vulnerable_count = vuln_count
        if scan_result.errors:
            scan.error_message = "; ".join(scan_result.errors[:3])

        session.commit()
        emit_progress(scan_id, 'complete', 100, 'Scan completed')

    except Exception as exc:
        logger.exception("Error executing container scan: %s", exc)
        try:
            scan = session.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(exc)
                scan.completed_at = datetime.utcnow()
                session.commit()
        except Exception:
            pass
        emit_progress(scan_id, 'error', -1, f"Scan failed: {str(exc)}")
    finally:
        session.close()

@celery_app.task(bind=True, name="app.tasks.source_scan_tasks.run_binary_scan")
def run_binary_scan(self, scan_id: str, target: str, scan_depth: str, repository: str = None):
    session = get_sync_session()
    try:
        scan = session.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            logger.error(f"Scan job {scan_id} not found")
            return
        
        scan.status = "running"
        session.commit()
        
        emit_progress(scan_id, 'scan_start', 5, 'Initializing scan...')
        
        emit_progress(scan_id, 'scanning', 30, 'Scanning binary...')
        scanner = BinaryScanner()
        scan_target = ScanTarget(
            path=target,
            scan_type="binary",
            depth=scan_depth,
            repository=repository,
        )
        scan_result = scanner.scan(scan_target)

        emit_progress(scan_id, 'saving_findings', 70, 'Saving findings...')
        created_assets = []
        qs_count = 0
        hybrid_count = 0
        vuln_count = 0

        for f in scan_result.findings:
            orm_kwargs = f.to_orm_kwargs()
            crypto_asset = CryptoAsset(
                scan_id=scan.id,
                **orm_kwargs,
            )
            session.add(crypto_asset)
            created_assets.append(crypto_asset)

            pqc = (f.pqc_status or "").upper()
            if pqc == "QUANTUM_SAFE":
                qs_count += 1
            elif pqc == "HYBRID_READY":
                hybrid_count += 1
            elif pqc == "VULNERABLE":
                vuln_count += 1
            else:
                vuln_count += 1

        emit_progress(scan_id, 'building_cbom', 90, 'Building CBOM...')
        cbom = build_cbom(
            scan_id=str(scan.id),
            target=target,
            assets=scan_result.findings,
        )
        cbom_json = cbom_to_json_string(cbom)
        cbom_record = CBOMRecord(
            scan_id=scan.id,
            cyclonedx_json=cbom_json,
        )
        session.add(cbom_record)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_assets = len(created_assets)
        scan.quantum_safe_count = qs_count
        scan.hybrid_count = hybrid_count
        scan.vulnerable_count = vuln_count
        if scan_result.errors:
            scan.error_message = "; ".join(scan_result.errors[:3])

        session.commit()
        emit_progress(scan_id, 'complete', 100, 'Scan completed')

    except Exception as exc:
        logger.exception("Error executing binary scan: %s", exc)
        try:
            scan = session.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(exc)
                scan.completed_at = datetime.utcnow()
                session.commit()
        except Exception:
            pass
        emit_progress(scan_id, 'error', -1, f"Scan failed: {str(exc)}")
    finally:
        session.close()
