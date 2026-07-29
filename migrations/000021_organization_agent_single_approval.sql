DROP TRIGGER IF EXISTS organization_agent_review_separation_trigger
    ON organization_agent_reviews;

DROP FUNCTION IF EXISTS enforce_organization_agent_review_separation();
