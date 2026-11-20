-- R2.12a: fail closed when either human's previously granted authority
-- has been withdrawn in the append-only R2.7/R2.8 operator denylist.
-- Only additive guards: no host, keys, live resource or privileges created.
-- These statements run inside the same D1 write transaction as each action.

CREATE TRIGGER async_revocation_actor_authority_guard
BEFORE INSERT ON processing_async_revocation_requests
WHEN EXISTS(
  SELECT 1 FROM processing_redrive_revocations r
  WHERE r.kind='operator' AND r.target=NEW.actor_subject
)
BEGIN SELECT RAISE(ABORT,'ASYNC_REVOCATION_ACTOR_REVOKED'); END;

CREATE TRIGGER async_revocation_approval_authority_guard
BEFORE UPDATE OF status ON processing_async_revocation_requests
WHEN OLD.status='pending' AND NEW.status='approved'
  AND EXISTS(
    SELECT 1 FROM processing_redrive_revocations r
    WHERE r.kind='operator'
      AND (r.target=OLD.actor_subject OR r.target=NEW.approver_subject)
  )
BEGIN SELECT RAISE(ABORT,'ASYNC_REVOCATION_APPROVER_REVOKED'); END;

-- The original 0024 approval guard already excludes a revoked approver.
-- Extend that protection to the operator who initiated the pending request.
CREATE TRIGGER async_redrive_approval_operator_authority_guard
BEFORE INSERT ON processing_async_redrive_approvals
WHEN EXISTS(
  SELECT 1 FROM processing_async_redrive_requests p
  JOIN processing_redrive_revocations r
    ON r.kind='operator' AND r.target=p.operator_subject
  WHERE p.id=NEW.request_id
)
BEGIN SELECT RAISE(ABORT,'ASYNC_REDRIVE_OPERATOR_REVOKED'); END;

-- Defense in depth against a separately crafted SQL transition. A pending
-- proposal never becomes approved after either principal is revoked.
CREATE TRIGGER async_redrive_approval_transition_authority_guard
BEFORE UPDATE OF status ON processing_async_redrive_requests
WHEN OLD.status='pending' AND NEW.status='approved'
  AND EXISTS(
    SELECT 1 FROM processing_redrive_revocations r
    WHERE r.kind='operator'
      AND (r.target=OLD.operator_subject OR r.target=NEW.approver_subject)
  )
BEGIN SELECT RAISE(ABORT,'ASYNC_REDRIVE_AUTHORITY_REVOKED'); END;
