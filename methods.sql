/*
UNIFIED FEATURE TABLE FOR ACCESS ANOMALY DETECTION
    - Access Velocity (AV1–AV4)
    - Role Violation (RV1)
    - Location/Device-Based (LD1, LD2)
    - Time-Based (TB1)
*/

WITH

-- *************************************************************************************************************************************************************
-- AV1 – Access Volume Spike Detection
-- Detects events where records_viewed is unusually high or low compared to the system-wide baseline (5th and 95th percentile).
bounds AS (
    SELECT
        percentile_cont(0.05) WITHIN GROUP (ORDER BY records_viewed) AS p5,
        percentile_cont(0.95) WITHIN GROUP (ORDER BY records_viewed) AS p95
    FROM access_logs
),
AV1 AS (
    SELECT
        a.event_id,
        CASE
            WHEN a.records_viewed < b.p5 THEN TRUE
            WHEN a.records_viewed > b.p95 THEN TRUE
            ELSE FALSE
        END AS AV1_is_spike
    FROM access_logs a
    CROSS JOIN bounds b
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV2 – Unauthorized Access Velocity
-- Measures how many records a user accesses from unauthorized resources.
AV2 AS (
    SELECT
        user_id,
        SUM(records_viewed) AS AV2_total_records,
        SUM(
            CASE
                WHEN is_authorized = 'FALSE' THEN records_viewed
                ELSE 0
            END
        ) AS AV2_unauth_records,
        CASE
            WHEN SUM(records_viewed) = 0 THEN 0::numeric
            ELSE
                ROUND(
                    SUM(CASE WHEN is_authorized = 'FALSE' THEN records_viewed ELSE 0 END)::numeric
                    / SUM(records_viewed)::numeric,
                    3
                )
        END AS AV2_unauth_ratio
    FROM access_logs
    GROUP BY user_id
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV3 - Sensitive Resource Velocity
-- Counts how many sensitive resources (resource_sens = TRUE) the user accesses in rapid succession.
AV3 AS (
    SELECT
        user_id,
        SUM(records_viewed) AS AV3_total_records,
        SUM(
            CASE
                WHEN resource_sens = 'TRUE' THEN records_viewed
                ELSE 0
            END
        ) AS AV3_sensitive_records,
        CASE
            WHEN SUM(records_viewed) = 0 THEN 0::numeric
            ELSE
                ROUND(
                    SUM(CASE WHEN resource_sens = 'TRUE' THEN records_viewed ELSE 0 END)::numeric
                    / SUM(records_viewed)::numeric,
                    3
                )
        END AS AV3_sensitive_ratio
    FROM access_logs
    GROUP BY user_id
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- AV3 - First-Time Access
-- Identifies when a user accesses a resource they have never interacted with before.
AV4 AS (
    SELECT
        event_id,
        CASE
            WHEN ROW_NUMBER() OVER (
                    PARTITION BY user_id, resource_accessed
                    ORDER BY access_timestamp
                 ) = 1
            THEN TRUE
            ELSE FALSE
        END AS AV4_is_first_time
    FROM access_logs
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- ROLE VIOLATION METHODS
-- RV1 Abnormal Access
-- (e.g., pilots reading payroll data)
RV1 AS (
    SELECT
        event_id,
        CASE
            /* HR allowed */
            WHEN user_role = 'HR'
             AND resource_accessed IN ('hr_files', 'payroll_records')
             AND access_type = 'read'
            THEN FALSE

            /* Customer Service allowed */
            WHEN user_role = 'Customer Service'
             AND resource_accessed = 'customer_table'
            THEN FALSE

            /* Finance allowed */
            WHEN user_role = 'Finance'
             AND resource_accessed = 'payroll_records'
            THEN FALSE

            /* IT allowed everything */
            WHEN user_role = 'IT'
            THEN FALSE

            /* Pilot allowed */
            WHEN user_role = 'Pilot'
             AND resource_accessed IN ('flight_logs', 'maintenance_logs')
             AND access_type = 'read'
            THEN FALSE

            /* Everything else is abnormal */
            ELSE TRUE
        END AS RV1_is_role_violation
    FROM access_logs
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- LOCATION DEVICE-BasED METHODS
-- LD1 - Location Velocity
-- Detects rapid or impossible travel scenarios (e.g., two distant logins too close together in time).
LD1_ordered AS (
    SELECT
        event_id,
        user_id,
        location,
        access_timestamp,
        LAG(location) OVER (
            PARTITION BY user_id
            ORDER BY access_timestamp
        ) AS prev_location,
        LAG(access_timestamp) OVER (
            PARTITION BY user_id
            ORDER BY access_timestamp
        ) AS prev_timestamp
    FROM access_logs
),
LD1 AS (
    SELECT
        event_id,
        CASE
            WHEN prev_timestamp IS NULL THEN FALSE
            WHEN location <> prev_location
                 AND access_timestamp - prev_timestamp < INTERVAL '2 hours'
            THEN TRUE
            ELSE FALSE
        END AS LD1_impossible_travel
    FROM LD1_ordered
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- LD2 - Device Velocity
-- Flags unusual or rapid device switching relative to normal behavior.
LD2_ordered AS (
    SELECT
        event_id,
        user_id,
        device_type,
        access_timestamp,
        LAG(device_type) OVER (
            PARTITION BY user_id
            ORDER BY access_timestamp
        ) AS prev_device_type,
        LAG(access_timestamp) OVER (
            PARTITION BY user_id
            ORDER BY access_timestamp
        ) AS prev_timestamp
    FROM access_logs
),
LD2 AS (
    SELECT
        event_id,
        CASE
            WHEN prev_timestamp IS NULL THEN FALSE
            WHEN device_type <> prev_device_type
                 AND access_timestamp - prev_timestamp <= INTERVAL '30 minutes'
            THEN TRUE
            ELSE FALSE
        END AS LD2_rapid_device_switch
    FROM LD2_ordered
),
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- TIME-BASED METHOD
-- TB1 - Off-Hours Velocity
-- Measures bursts of activity that occur during non-standard times.
TB1 AS (
    SELECT
        event_id,
        CASE
            /* Weekend: 0 = Sunday, 6 = Saturday */
            WHEN EXTRACT(DOW FROM access_timestamp) IN (0, 6) THEN TRUE

            /* Before 08:00AM or after 6:00PM on weekdays */
            WHEN EXTRACT(HOUR FROM access_timestamp) < 8
              OR EXTRACT(HOUR FROM access_timestamp) > 18
            THEN TRUE

            ELSE FALSE
        END AS TB1_is_off_hours
    FROM access_logs
)
-- *************************************************************************************************************************************************************


-- *************************************************************************************************************************************************************
-- FINAL FEATURE TABLE
SELECT
    a.event_id,
    a.user_id,
    a.user_role,
    a.resource_accessed,
    a.access_type,
    a.location,
    a.device_type,
    a.access_timestamp,
    a.records_viewed,

    /* Access Velocity Features */
    AV1.AV1_is_spike,
    AV2.AV2_unauth_ratio,
    AV3.AV3_sensitive_ratio,
    AV4.AV4_is_first_time,

    /* Role Violation Feature */
    RV1.RV1_is_role_violation,

    /* Location / Device Features */
    LD1.LD1_impossible_travel,
    LD2.LD2_rapid_device_switch,

    /* Time-Based Feature */
    TB1.TB1_is_off_hours

FROM access_logs a
LEFT JOIN AV1 ON a.event_id = AV1.event_id
LEFT JOIN AV2 ON a.user_id = AV2.user_id
LEFT JOIN AV3 ON a.user_id = AV3.user_id
LEFT JOIN AV4 ON a.event_id = AV4.event_id
LEFT JOIN RV1 ON a.event_id = RV1.event_id
LEFT JOIN LD1 ON a.event_id = LD1.event_id
LEFT JOIN LD2 ON a.event_id = LD2.event_id
LEFT JOIN TB1 ON a.event_id = TB1.event_id
ORDER BY a.access_timestamp, a.user_id;
-- *************************************************************************************************************************************************************
