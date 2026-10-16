<?php
declare(strict_types=1);

namespace Camp;

function catalog(): array
{
    $text = ['type' => 'text', 'max' => 2000];
    $short = ['type' => 'text', 'max' => 160];
    $date = ['type' => 'date'];
    $datetime = ['type' => 'datetime'];
    $number = ['type' => 'integer', 'min' => 0, 'max' => 100000000];
    $list = ['type' => 'list', 'max' => 40];
    $status = static fn(array $values): array => ['type' => 'enum', 'values' => $values];
    $ref = static fn(string $target): array => ['type' => 'reference', 'target' => $target];
    $make = static fn(string $label, string $scope, array $fields, array $required): array =>
        compact('label', 'scope', 'fields', 'required');
    return [
        'campers' => $make('Camper administrative identity', 'identity', [
            'display_name' => $short, 'arrival_date' => $date, 'departure_date' => $date,
        ], ['display_name']),
        'reservations' => $make('Reservations', 'camper', [
            'arrival_date' => $date, 'departure_date' => $date,
            'status' => $status(['requested', 'confirmed', 'cancelled']),
        ], ['arrival_date', 'departure_date', 'status']),
        'waivers' => $make('Administrative waiver declarations; no health narrative', 'camper', [
            'document_reference' => $short, 'signed_on' => $date,
            'status' => $status(['pending', 'signed', 'withdrawn']),
        ], ['document_reference', 'status']),
        'consents' => $make('Administrative consent declarations', 'camper', [
            'purpose' => $short, 'document_reference' => $short, 'signed_on' => $date,
            'status' => $status(['pending', 'granted', 'withdrawn']),
        ], ['purpose', 'document_reference', 'status']),
        'demographics' => $make('Administrative contact and demographic data; no clinical fields', 'camper', [
            'contact_name' => $short, 'contact_phone' => $short,
            'mailing_address' => $text, 'preferred_language' => $short,
        ], ['contact_name', 'contact_phone']),
        'rosters' => $make('Administrative cabin and group assignments', 'camper', [
            'cabin' => $short, 'group_name' => $short, 'arrival_date' => $date, 'departure_date' => $date,
        ], ['cabin', 'group_name']),
        'policies' => $make('Administrative policies; no individual records', 'none', [
            'title' => $short, 'body' => $text, 'effective_on' => $date,
        ], ['title', 'body', 'effective_on']),
        'templates' => $make('Blank administrative document templates', 'none', [
            'name' => $short, 'body' => $text, 'version' => $short,
        ], ['name', 'body', 'version']),
        'staff_onboarding' => $make('Administrative onboarding checklist; no passwords or health data', 'none', [
            'staff_reference' => $short, 'checklist' => $list,
            'status' => $status(['pending', 'in_progress', 'complete']),
        ], ['staff_reference', 'checklist', 'status']),
        'compliance_reports' => $make('Administrative compliance summaries; no individual health records', 'none', [
            'period' => $short, 'reviewed_items' => $number, 'open_items' => $number, 'summary' => $text,
        ], ['period', 'reviewed_items', 'open_items']),
        'clinical_notes' => $make('Clinical notes (clinical staff only)', 'camper', [
            'note' => $text, 'recorded_on' => $date,
        ], ['note', 'recorded_on']),
        'prescriptions' => $make('Prescription requests; not medication administration', 'camper', [
            'medication' => $short, 'instructions' => $text, 'prescriber' => $short,
        ], ['medication', 'instructions']),
        'medication_schedules' => $make('Clinical medication schedule records; requires independent clinical verification', 'camper', [
            'prescription_id' => $ref('prescriptions'), 'scheduled_at' => $datetime,
            'dose_instructions' => $short, 'status' => $status(['planned', 'verified', 'cancelled']),
        ], ['prescription_id', 'scheduled_at', 'dose_instructions', 'status']),
        'medication_administrations' => $make('Clinical administration documentation; not a validated eMAR or dosing engine', 'camper', [
            'schedule_id' => $ref('medication_schedules'), 'recorded_at' => $datetime,
            'status' => $status(['given', 'refused', 'held', 'missed']), 'note' => $text,
        ], ['schedule_id', 'recorded_at', 'status']),
        'medication_stock' => $make('Clinical medication inventory ledger; no dispensing automation', 'none', [
            'medication' => $short, 'lot_reference' => $short, 'quantity_units' => $number, 'expires_on' => $date,
        ], ['medication', 'lot_reference', 'quantity_units', 'expires_on']),
        'clinical_incidents' => $make('Clinical incident details; never exposed through general incidents', 'camper', [
            'occurred_at' => $datetime, 'clinical_report' => $text, 'follow_up' => $text,
        ], ['occurred_at', 'clinical_report']),
        'allergies' => $make('Dietary allergy declarations', 'camper', [
            'allergen' => $short, 'severity' => $status(['unknown', 'mild', 'moderate', 'severe']),
        ], ['allergen', 'severity']),
        'care_profiles' => $make('Minimum necessary counselor care instructions', 'camper', [
            'care_instructions' => $text, 'emergency_action' => $text,
        ], ['care_instructions']),
        'behavioral_plans' => $make('Behavioral support instructions', 'camper', [
            'support_instructions' => $text, 'deescalation' => $text,
        ], ['support_instructions']),
        'behavioral_tracking' => $make('Behavioral observations and intervention tracking', 'camper', [
            'observed_at' => $datetime, 'observation' => $text, 'intervention' => $text,
        ], ['observed_at', 'observation']),
        'consultation_notes' => $make('Behavioral consultation notes', 'camper', [
            'consulted_on' => $date, 'note' => $text,
        ], ['consulted_on', 'note']),
        'behavior_health_context' => $make('Clinician-curated behavior-relevant health context; no full clinical chart', 'camper', [
            'relevant_precautions' => $text, 'reviewed_on' => $date,
        ], ['relevant_precautions', 'reviewed_on']),
        'accommodations' => $make('Accommodation requests', 'camper', [
            'request' => $text, 'status' => $status(['requested', 'planned', 'fulfilled']),
        ], ['request', 'status']),
        'equipment' => $make('Adaptive equipment', 'none', [
            'name' => $short, 'availability' => $status(['available', 'reserved', 'repair']),
        ], ['name', 'availability']),
        'facility_audits' => $make('Accessibility facility audits; no camper records', 'none', [
            'location' => $short, 'audited_on' => $date, 'findings' => $text,
            'status' => $status(['open', 'remediation', 'complete']),
        ], ['location', 'audited_on', 'findings', 'status']),
        'work_orders' => $make('Facility work requests (no camper data)', 'none', [
            'location' => $short, 'request' => $text,
            'status' => $status(['open', 'in_progress', 'closed']),
        ], ['location', 'request', 'status']),
        'safety_notices' => $make('General safety notices (no camper data)', 'none', [
            'title' => $short, 'instructions' => $text,
        ], ['title', 'instructions']),
        'emergency_plans' => $make('Facility emergency plans (no camper data)', 'none', [
            'location' => $short, 'instructions' => $text,
        ], ['location', 'instructions']),
        'inspections' => $make('Facility inspections; no camper records', 'none', [
            'location' => $short, 'inspected_on' => $date, 'findings' => $text,
            'status' => $status(['open', 'action_required', 'complete']),
        ], ['location', 'inspected_on', 'findings', 'status']),
        'emergency_alerts' => $make('Facility emergency alerts; no camper records', 'none', [
            'location' => $short, 'instructions' => $text,
            'status' => $status(['active', 'resolved']),
        ], ['location', 'instructions', 'status']),
        'sanitation' => $make('Sanitation and sensory environment tasks', 'none', [
            'location' => $short, 'task' => $text,
            'status' => $status(['open', 'complete']),
        ], ['location', 'task', 'status']),
        'supplies' => $make('Supply inventory', 'none', [
            'name' => $short, 'quantity' => $number,
        ], ['name', 'quantity']),
        'sensory_setup' => $make('Sensory-room environment setup tasks; no camper records', 'none', [
            'location' => $short, 'instructions' => $text,
            'status' => $status(['open', 'in_progress', 'complete']),
        ], ['location', 'instructions', 'status']),
        'supply_requests' => $make('Housekeeping supply requests; no camper data', 'none', [
            'item' => $short, 'quantity' => $number, 'location' => $short,
        ], ['item', 'quantity', 'location']),
        'activities' => $make('Activity schedule', 'none', [
            'name' => $short, 'scheduled_on' => $date, 'description' => $text,
            'capacity' => ['type' => 'integer', 'min' => 1, 'max' => 1000],
            'status' => $status(['draft', 'available', 'closed']),
        ], ['name', 'scheduled_on', 'capacity', 'status']),
        'activity_adaptations' => $make('Activity adaptations; no clinical notes', 'camper', [
            'activity_id' => $ref('activities'), 'instructions' => $text,
        ], ['activity_id', 'instructions']),
        'camper_safety_alerts' => $make('Clinician-curated activity safety instructions; no full health history', 'camper', [
            'precaution' => $short, 'instructions' => $text, 'reviewed_on' => $date,
        ], ['precaution', 'instructions', 'reviewed_on']),
        'participation' => $make('Activity participation and attendance; no clinical notes', 'camper', [
            'activity_id' => $ref('activities'),
            'status' => $status(['registered', 'attended', 'absent', 'excused', 'cancelled']),
            'adaptation_feedback' => $text,
        ], ['activity_id', 'status']),
        'activity_signups' => $make('Activity enrollment', 'camper', [
            'activity_id' => $ref('activities'),
            'status' => $status(['enrolled', 'cancelled']),
        ], ['activity_id']),
        'daily_logs' => $make('Counselor daily observations', 'camper', [
            'recorded_on' => $date, 'observation' => $text,
        ], ['recorded_on', 'observation']),
        'incidents' => $make('Camper incident reports', 'camper', [
            'occurred_on' => $date, 'report' => $text,
        ], ['occurred_on', 'report']),
        'menus' => $make('Published menu ingredients and declared allergens', 'none', [
            'name' => $short, 'service_date' => $date, 'ingredients' => $list,
            'allergens' => $list, 'status' => $status(['draft', 'published']),
        ], ['name', 'service_date', 'ingredients', 'allergens', 'status']),
        'special_meals' => $make('Special meal requests; dietary details only', 'camper', [
            'menu_id' => $ref('menus'), 'request' => $text,
            'status' => $status(['requested', 'planned', 'served']),
        ], ['menu_id', 'request', 'status']),
        'dietary_profiles' => $make('Dietary instructions; no clinical notes', 'camper', [
            'instructions' => $text, 'excluded_ingredients' => $list,
        ], ['instructions', 'excluded_ingredients']),
        'billing' => $make('Billing ledger; never card or health data', 'own', [
            'reference' => $short, 'amount_cents' => $number,
            'status' => $status(['pending', 'paid', 'void']),
        ], ['reference', 'amount_cents', 'status']),
        'payroll' => $make('Payroll ledger; no bank details', 'none', [
            'employee_reference' => $short, 'amount_cents' => $number, 'period_end' => $date,
        ], ['employee_reference', 'amount_cents', 'period_end']),
        'grants' => $make('Grant funding ledger', 'none', [
            'name' => $short, 'amount_cents' => $number, 'fiscal_year' => $short,
        ], ['name', 'amount_cents', 'fiscal_year']),
        'public_content' => $make('Public and mission content drafts; publishing requires a separate approved workflow', 'none', [
            'title' => $short, 'body' => $text,
            'status' => $status(['draft', 'approved', 'published']),
        ], ['title', 'body', 'status']),
        'budgets' => $make('Budget planning ledger; no health or payment credentials', 'none', [
            'name' => $short, 'fiscal_year' => $short, 'amount_cents' => $number,
        ], ['name', 'fiscal_year', 'amount_cents']),
        'financial_approvals' => $make('Financial approval decisions; does not move funds', 'none', [
            'reference' => $short, 'amount_cents' => $number,
            'status' => $status(['pending', 'approved', 'declined']), 'decision_note' => $text,
        ], ['reference', 'amount_cents', 'status']),
        'grant_applications' => $make('Grant applications; no health narratives', 'own', [
            'grant_id' => $ref('grants'), 'requested_cents' => $number,
            'statement' => $text, 'status' => $status(['submitted', 'approved', 'declined']),
        ], ['grant_id', 'requested_cents', 'statement', 'status']),
        'aggregate_reports' => $make('Manually approved nonidentifying aggregate reports', 'none', [
            'period' => $short, 'occupancy_count' => $number, 'revenue_cents' => $number,
            'satisfaction_percent' => ['type' => 'integer', 'min' => 0, 'max' => 100],
        ], ['period', 'occupancy_count', 'revenue_cents']),
        'audit_events' => $make('Read-only persistent audit metadata; no request bodies or clinical contents', 'none', [
            'event' => $short, 'resource' => $short, 'record_id' => $number,
            'actor_id' => $number, 'client_id' => $number, 'outcome' => $short,
            'occurred_at' => $datetime, 'request_id' => $short,
        ], []),
        'configuration' => $make('Read-only nonsecret runtime limits; never database settings or keys', 'none', [
            'environment' => $short, 'https_required' => ['type' => 'boolean'],
            'session_ttl_seconds' => $number, 'max_body_bytes' => $number, 'max_list_size' => $number,
        ], []),
    ];
}

// Explicit resource grants only. Multiple memberships add grants, never an administrator bypass.
function roleGrants(): array
{
    $grants = [];
    $add = static function (int $role, array $resources, array $actions, string $scope = 'all') use (&$grants): void {
        foreach ($resources as $resource) {
            foreach ($actions as $action) {
                $grants[$role][$resource][$action][] = $scope;
            }
        }
    };
    $crud = ['read', 'create', 'update', 'delete'];
    $cru = ['read', 'create', 'update'];
    $add(1, ['aggregate_reports'], ['read']);
    $add(1, ['public_content'], $crud);
    $add(1, ['budgets', 'financial_approvals', 'grants', 'grant_applications'], $cru);
    $add(1, ['audit_events', 'configuration'], ['read']);
    $add(2, ['campers', 'reservations', 'waivers', 'consents', 'demographics', 'rosters', 'policies', 'templates', 'staff_onboarding', 'compliance_reports'], $crud);
    $add(2, ['aggregate_reports'], ['read', 'create', 'update']);
    $add(3, ['campers'], ['read']);
    $add(3, ['clinical_notes', 'prescriptions', 'allergies', 'care_profiles', 'dietary_profiles'], $crud);
    $add(3, ['medication_schedules', 'medication_administrations', 'medication_stock', 'clinical_incidents', 'behavior_health_context', 'camper_safety_alerts'], $cru);
    $add(3, ['incidents', 'daily_logs', 'behavioral_plans'], ['read']);
    $add(3, ['incidents'], ['update']);
    $add(4, ['campers', 'behavior_health_context'], ['read']);
    $add(4, ['behavioral_plans', 'behavioral_tracking', 'consultation_notes'], $cru);
    $add(5, ['campers'], ['read']);
    $add(5, ['accommodations'], ['read', 'update']);
    $add(5, ['equipment'], $crud);
    $add(5, ['facility_audits'], $cru);
    $add(5, ['work_orders'], ['read', 'create']);
    $add(6, ['campers', 'safety_notices', 'camper_safety_alerts'], ['read']);
    $add(6, ['activities', 'activity_adaptations'], $crud);
    $add(6, ['participation'], ['read', 'update']);
    $add(6, ['activity_signups'], ['read']);
    $add(7, ['campers', 'care_profiles', 'daily_logs'], ['read'], 'assigned');
    $add(7, ['daily_logs', 'incidents'], ['create'], 'assigned');
    $add(8, ['work_orders', 'safety_notices', 'emergency_plans', 'emergency_alerts'], ['read', 'update']);
    $add(8, ['inspections'], $cru);
    $add(9, ['sanitation', 'sensory_setup'], ['read', 'update']);
    $add(9, ['supply_requests'], ['read', 'create']);
    $add(9, ['safety_notices'], ['read']);
    $add(10, ['allergies', 'dietary_profiles'], ['read']);
    $add(10, ['menus'], $cru);
    $add(10, ['special_meals'], ['read', 'update']);
    $add(11, ['billing', 'payroll', 'grants', 'grant_applications'], $crud);
    $add(11, ['budgets'], $cru);
    $add(11, ['financial_approvals'], ['read']);
    $add(11, ['aggregate_reports'], ['read', 'create', 'update']);
    $add(12, ['campers'], ['read'], 'own');
    $add(12, ['reservations', 'accommodations', 'prescriptions', 'allergies', 'grant_applications', 'special_meals', 'activity_signups'], $cru, 'own');
    $add(12, ['menus', 'activities', 'grants'], ['read'], 'published');
    return $grants;
}
