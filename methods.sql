select*
from access_logs;

-- *************************************************************************************************************************************************************
-- AV1 – Access Volume Spike Detection
-- Detects events where records_viewed is unusually high or low compared to the system-wide baseline (5th and 95th percentile).
with bounds as (
    select
        percentile_cont(0.05) within group (order by records_viewed) as p5,
        percentile_cont(0.95) within group (order by records_viewed) as p95
    from access_logs
)

select
    a.event_id,
    a.user_id,
    a.records_viewed,
    b.p5,
    b.p95,
    case
        when a.records_viewed < b.p5 then TRUE     -- Very low outlier
        when a.records_viewed > b.p95 then TRUE    -- Very high outlier
        else FALSE
    end as is_av1_spike
from access_logs a
cross join bounds b
order by a.event_id;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV2 – Unauthorized Access Velocity
-- Measures how many records a user accesses from unauthorized resources.
select 
    user_id,
    
    -- Total records viewed by the user
    sum(records_viewed) as total_records_viewed,
    
    -- Records viewed from unauthorized resources
    sum(
        case 
            when is_authorized = FALSE then records_viewed
            else 0
        end
    ) as unauthorized_records_viewed,
    
    -- Ratio of unauthorized access
    case 
        when sum(records_viewed) = 0 then 0
        else round(
            sum(case when is_authorized = FALSE then records_viewed else 0 end)::numeric
            /
            sum(records_viewed),
        3)
    end as unauthorized_ratio

from access_logs
group by user_id
order by unauthorized_records_viewed DESC;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV3 - Sensitive Resource Velocity
-- Counts how many sensitive resources (resource_sens = TRUE) the user accesses in rapid succession.
select
    user_id, -- Total records viewed
    sum(records_viewed) as total_records_viewed, -- Records viewed from sensitive resources
    sum(
        case 
            when resource_sens = TRUE then records_viewed
            else 0
        end
    ) as sensitive_records_viewed,

    case -- Share of a user's activity that is sensitive
        when sum(records_viewed) = 0 then 0
        else round(
            sum(case when resource_sens = TRUE then records_viewed else 0 end)::numeric
            / sum(records_viewed),
            3
        )
    end as sensitive_ratio
from access_logs
group by user_id
order by user_id desc;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV4 - First-Time Access
-- Identifies when a user accesses a resource they have never interacted with before.
select
    event_id,
    user_id,
    resource_accessed,
    records_viewed,
    access_timestamp,
    case 
        when ROW_NUMBER() OVER (
                 PARTITION BY user_id, resource_accessed
                 order by access_timestamp
             ) = 1
        then TRUE
        else FALSE
    end as is_av5_first_time
from access_logs
order by user_id, access_timestamp, resource_accessed;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- ROLE VIOLATION METHODS
-- RV1 Abnormal Access
-- (e.g., pilots reading payroll data)
select distinct
    user_role,
    access_type,
    resource_accessed,
    case
        -- HR allowed
        when user_role = 'HR'
         and resource_accessed = 'hr_files' then FALSE
        when user_role = 'HR'
         and resource_accessed = 'payroll_records'
         and access_type = 'read' then FALSE

        -- Customer Service allowed
        when user_role = 'Customer Service'
         and resource_accessed = 'customer_table' then FALSE

        -- Finance allowed
        when user_role = 'Finance'
         and resource_accessed = 'payroll_records' then FALSE

        -- IT allowed to everything
        when user_role = 'IT' then FALSE

        -- Pilot allowed
        when user_role = 'Pilot'
         and resource_accessed = 'flight_logs' then FALSE
        when user_role = 'Pilot'
         and resource_accessed = 'maintenance_logs'
         and access_type = 'read' then FALSE

        -- Everything else is abnormal
        else TRUE
    end as is_abnormal
from access_logs
order by user_role, resource_accessed, access_type;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- LOCATION DEVICE-BasED METHODS
-- LD1 - Location Velocity
-- Detects rapid or impossible travel scenarios (e.g., two distant logins too close together in time).
with ordered_logs as (
    select
        event_id,
        user_id,
        location,
        access_timestamp,
        LAG(location) over (partition by user_id order by access_timestamp) as prev_location,
        LAG(access_timestamp) OVER (partition by user_id order by access_timestamp) as prev_timestamp
    from access_logs
)
select
    event_id,
    user_id,
    location,
    access_timestamp,
    prev_location,
    prev_timestamp,
    case
        when prev_timestamp is null then FALSE
        when location <> prev_location
             and access_timestamp - prev_timestamp < interval '2 hours'
        then TRUE
        else FALSE
    end as impossible_travel
from ordered_logs
order by user_id, access_timestamp;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- LD2 - Device Velocity
-- Flags unusual or rapid device switching relative to normal behavior.
with ordered_logs AS (
    select
        event_id,
        user_id,
        device_type,
        access_timestamp,
        LAG(device_type) over (
            partition by user_id 
            order by access_timestamp
        ) AS prev_device_type,
        LAG(access_timestamp) over (
            partition by user_id 
            order by access_timestamp
        ) as prev_timestamp
    from access_logs
)
select
    event_id,
    user_id,
    device_type,
    access_timestamp,
    prev_device_type,
    prev_timestamp,
    case
        -- first event for the user
        when prev_timestamp is null then FALSE
        
        -- rapid device switch: different device within 30 minutes
        when device_type <> prev_device_type
             and access_timestamp - prev_timestamp <= INTERVAL '30 minutes'
        then TRUE
        
        else FALSE
    end as is_ld2_rapid_device_switch
from ordered_logs
order by user_id, access_timestamp;
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- TIME-BASED METHOD
-- TB1 - Off-Hours Velocity
-- Measures bursts of activity that occur during non-standard times.
select 
    event_id,
    user_id,
    access_timestamp,
    case 
        -- Weekend check: Saturday (6) or Sunday (0)
        when extract(DOW from access_timestamp) IN (0, 6) then TRUE
        
        -- Off-hours check: before 08:00 or after 18:00
        when extract(hour from access_timestamp) < 8 
          OR extract(hour from access_timestamp) > 18 then TRUE
        
        -- Otherwise, normal hours
        else FALSE
    end as outside_standard_hrs
from access_logs
order by event_id, user_id, access_timestamp;
-- *************************************************************************************************************************************************************
