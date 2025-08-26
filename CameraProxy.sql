-- This script creates the necessary tables and sample data for the iCamera Proxy application.
-- It is designed to be run by the installer to set up the HSQLDB database.

-- =================================================================================
-- Table: msp_camera_adapter
-- Purpose: Stores camera adapter implementation details.
-- Used by: The `fileCatalystCheck` query to determine if FileCatalyst is needed.
-- =================================================================================

-- Drop the table if it exists to ensure a clean setup.
DROP TABLE public.msp_camera_adapter IF EXISTS;

-- Create the table.
-- HSQLDB uses 'IDENTITY' for auto-incrementing primary keys.
CREATE TABLE public.msp_camera_adapter (
    id INTEGER IDENTITY PRIMARY KEY,
    adapter_impl_id_fk INTEGER NOT NULL
);

-- Create an index for performance on the foreign key column.
CREATE INDEX idx_msp_camera_adapter_fk ON public.msp_camera_adapter (adapter_impl_id_fk);

-- Insert sample data.
-- The value 1017 is specifically checked by the installer to enable FileCatalyst.
INSERT INTO public.msp_camera_adapter (adapter_impl_id_fk) VALUES (1017);
INSERT INTO public.msp_camera_adapter (adapter_impl_id_fk) VALUES (1018);


-- =================================================================================
-- Table: mspgbl_camera_proxy
-- Purpose: Stores information about configured camera proxies.
-- Used by: The `installInfo` query to retrieve basic proxy details after setup.
-- =================================================================================

-- Drop the table if it exists.
DROP TABLE public.mspgbl_camera_proxy IF EXISTS;

-- Create the table.
CREATE TABLE public.mspgbl_camera_proxy (
    id INTEGER IDENTITY PRIMARY KEY,
    proxy_name VARCHAR(255) NOT NULL
);

-- Insert sample data for the proxy. The installer can query this after setup.
INSERT INTO public.mspgbl_camera_proxy (id, proxy_name) VALUES (1, 'Main Site Camera Proxy');