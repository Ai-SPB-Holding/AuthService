-- Ensure existing OAuth clients can use `grant_type=embedded_session` after grant checks were tightened.
UPDATE clients c
SET grant_types = array_append(c.grant_types, 'embedded_session')
WHERE NOT ('embedded_session' = ANY (c.grant_types));
