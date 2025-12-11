/*
UNIFIED FEATURE TABLE FOR ACCESS ANOMALY DETECTION
    - Access Velocity (AV1–AV4)
    - Role Violation (RV1)
    - LOCATION/Device-Based (LD1, LD2)
    - Time-Based (TB1)
*/

with

-- *************************************************************************************************************************************************************
-- AV1 – Access Volume Spike Detection
-- Detects events where records_viewed is unusually high or low compared to the system-wide baseline (5th and 95th percentile).
bounds as (
    select
        percentile_cont(0.05) within group (order by records_viewed) as p5,
        percentile_cont(0.95) within group (order by records_viewed) as p95
    from access_logs
),
AV1 as (
    select
        a.event_id,
        case
            when a.records_viewed < b.p5 then TRUE
            when a.records_viewed > b.p95 then TRUE
            else FALSE
        end as AV1isSpike
    from access_logs a
    CROSS JOIN bounds b
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV2 – Unauthorized Access Velocity
-- Measures how many records a user accesses from unauthorized resources.
AV2 as (
    select
        user_id,
        sum(records_viewed) as AV2_total_records,
        sum(
            case
                when is_authorized = 'FALSE' then records_viewed
                else 0
            end
        ) as AV2unauthRecords,
        case
            when sum(records_viewed) = 0 then 0::numeric
            else
                round(
                    sum(case when is_authorized = 'FALSE' then records_viewed else 0 end)::numeric
                    / sum(records_viewed)::numeric,
                    3
                )
        end as AV2unauthRatio
    from access_logs
    group by user_id
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV3 - Sensitive Resource Velocity
-- Counts how many sensitive resources (resource_sens = TRUE) the user accesses in rapid succession.
AV3 as (
    select
        user_id,
        sum(records_viewed) as AV3_total_records,
        sum(
            case
                when resource_sens = 'TRUE' then records_viewed
                else 0
            end
        ) as AV3senRecords,
        case
            when sum(records_viewed) = 0 then 0::numeric
            else
                ROUND(
                    sum(case when resource_sens = 'TRUE' then records_viewed else 0 end)::numeric
                    / sum(records_viewed)::numeric,
                    3
                )
        end as AV3senRatio
    from access_logs
    group by user_id
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV3 - First-Time Access
-- Identifies when a user accesses a resource they have never interacted with before.
AV4 as (
    select
        event_id,
        case
            when ROW_NUMBER() over (
                    partition by user_id, resource_accessed
                    order by access_timestamp
                 ) = 1
            then TRUE
            else FALSE
        end as AV4isFirstTime
    from access_logs
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- ROLE VIOLATION METHODS
-- RV1 Abnormal Access
-- (e.g., pilots reading payroll data)
RV1 as (
    select
        event_id,
        case
            /* HR allowed */
            when user_role = 'HR'
             and resource_accessed IN ('hr_files', 'payroll_records')
             and access_type = 'read'
            then FALSE

            /* Customer Service allowed */
            when user_role = 'Customer Service'
             and resource_accessed = 'customer_table'
            then FALSE

            /* Finance allowed */
            when user_role = 'Finance'
             and resource_accessed = 'payroll_records'
            then FALSE

            /* IT allowed everything */
            when user_role = 'IT'
            then FALSE

            /* Pilot allowed */
            when user_role = 'Pilot'
             and resource_accessed IN ('flight_logs', 'maintenance_logs')
             and access_type = 'read'
            then FALSE

            /* Everything else is abnormal */
            else TRUE
        end as RV1isRoleViolate
    from access_logs
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- LOCATION DEVICE-BASED METHODS
-- LD1 - LOCATION Velocity
-- Detects rapid or impossible travel scenarios (e.g., two distant logins too close together in time).
LD1_ordered as (
    select
        event_id,
        user_id,
        location,
        access_timestamp,
        lag(location) over (
            partition by user_id
            order by access_timestamp
        ) as prev_location,
        lag(access_timestamp) over (
            partition by user_id
            order by access_timestamp
        ) as prev_timestamp
    from access_logs
),
LD1 as (
    select
        event_id,
        case
            when prev_timestamp is null then FALSE
            when location <> prev_location
                 and access_timestamp - prev_timestamp < INTERVAL '2 hours'
            then TRUE
            else FALSE
        end as LD1isImpossTravel
    from LD1_ordered
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- LD2 - Device Velocity
-- Flags unusual or rapid device switching relative to normal behavior.
LD2_ordered as (
    select
        event_id,
        user_id,
        device_type,
        access_timestamp,
        lag(device_type) over (
            partition by user_id
            order by access_timestamp
        ) as prev_device_type,
        lag(access_timestamp) over (
            partition by user_id
            order by access_timestamp
        ) as prev_timestamp
    from access_logs
),
LD2 as (
    select
        event_id,
        case
            when prev_timestamp is null then FALSE
            when device_type <> prev_device_type
                 and access_timestamp - prev_timestamp <= INTERVAL '30 minutes'
            then TRUE
            else FALSE
        end as LD2isRdswitch
    from LD2_ordered
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- TIME-BasED METHOD
-- TB1 - Off-hours Velocity
-- Measures bursts of activity that occur during non-standard times.
TB1 as (
    select
        event_id,
        case
            /* Weekend: 0 = Sunday, 6 = Saturday */
            when extract(DOW from access_timestamp) IN (0, 6) then TRUE

            /* Before 08:00AM or after 6:00PM on weekdays */
            when extract(hour from access_timestamp) < 8
              OR extract(hour from access_timestamp) > 18
            then TRUE

            else FALSE
        end as TB1isOffHrs
    from access_logs
)
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- FINAL FEATURE TABLE
select
    a.event_id,
    a.user_id,
    a.user_role,
    a.resource_accessed,
    a.access_type,
    a.location,
    a.device_type,
    a.access_timestamp,
    a.records_viewed,
    a.is_privacy_violation,

    /* Access Velocity Features */
    AV1.AV1isSpike,
    AV2.AV2unauthRatio,
    AV3.AV3senRatio,
    AV4.AV4isFirstTime,

    /* Role Violation Feature */
    RV1.RV1isRoleViolate,

    /* LOCATION / Device Features */
    LD1.LD1isImpossTravel,
    LD2.LD2isRdswitch,

    /* Time-Based Feature */
    TB1.TB1isOffHrs

from access_logs a
left join AV1 on a.event_id = AV1.event_id
left join AV2 on a.user_id = AV2.user_id
left join AV3 on a.user_id = AV3.user_id
left join AV4 on a.event_id = AV4.event_id
left join RV1 on a.event_id = RV1.event_id
left join LD1 on a.event_id = LD1.event_id
left join LD2 on a.event_id = LD2.event_id
left join TB1 on a.event_id = TB1.event_id
order by a.access_timestamp, a.user_id;
-- *************************************************************************************************************************************************************