
-- TOC entry 3507 (class 0 OID 23410)
-- Dependencies: 251
-- Data for Name: contacto; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.contacto VALUES (1, 'Juan Pérez', 'Av. Principal 123', '+56987654321', 'juan.perez@email.com', '@juan_perez', 'https://juan.dev', NULL, 1);
INSERT INTO core.contacto VALUES (2, 'María González', 'Calle Comercio 456', '+56912345678', 'maria@empresa.com', '@maria_ceo', 'https://empresa.com', NULL, 2);
INSERT INTO core.contacto VALUES (3, 'Proveedor XYZ Ltda.', 'Industrial 789', '+56998877665', 'contacto@proveedorxyz.com', '@proveedorxyz', 'https://proveedorxyz.com', NULL, 3);
INSERT INTO core.contacto VALUES (4, 'Sebastian Parra', 'Pedro mira 820', '+56957910176', 'parra.sebastian91@gmail.com', '@seba_on_fire', 'http://www.la.que.cuelga', NULL, 1);


--
-- TOC entry 3511 (class 0 OID 23430)
-- Dependencies: 255
-- Data for Name: cuenta_bancaria; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.cuenta_bancaria VALUES (1, 'Tech Solutions SpA', 'Banco Estado', '12345678901', 'finanzas@techsolutions.com', '76543210-5', 1);
INSERT INTO core.cuenta_bancaria VALUES (2, 'Proveedor XYZ Ltda.', 'Banco Santander', '98765432109', 'admin@proveedorxyz.com', '87654321-3', 2);


--
-- TOC entry 3515 (class 0 OID 23450)
-- Dependencies: 259
-- Data for Name: modulo; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.modulo VALUES (1, 'Gestión de Usuarios', 'Administración de usuarios y accesos', true, 1);
INSERT INTO core.modulo VALUES (2, 'Gestión de Contactos', 'Administración de contactos', true, 1);
INSERT INTO core.modulo VALUES (3, 'Gestión de Organizaciones', 'Administración de organizaciones', true, 1);
INSERT INTO core.modulo VALUES (4, 'Reportes', 'Generación de reportes', false, 1);
INSERT INTO core.modulo VALUES (5, 'Ventas', 'Gestión de ventas', true, 2);
INSERT INTO core.modulo VALUES (6, 'Gestión de Bodega', 'Administracion de  almacenage', true, 1);



--
-- TOC entry 3509 (class 0 OID 23420)
-- Dependencies: 253
-- Data for Name: organizacion; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.organizacion VALUES (1, 'Tech Solutions SpA', '76543210', '5', 'Desarrollo de software', NULL, 2);
INSERT INTO core.organizacion VALUES (2, 'Proveedor XYZ Ltda.', '87654321', '3', 'Suministros industriales', NULL, 3);


--
-- TOC entry 3526 (class 0 OID 23510)
-- Dependencies: 270
-- Data for Name: organizacion_contacto; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.organizacion_contacto VALUES (2, 1);
INSERT INTO core.organizacion_contacto VALUES (3, 2);
INSERT INTO core.organizacion_contacto VALUES (4, 1);


--
-- TOC entry 3516 (class 0 OID 23458)
-- Dependencies: 260
-- Data for Name: organizacion_sistema; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.organizacion_sistema VALUES (1, 1);
INSERT INTO core.organizacion_sistema VALUES (1, 2);
INSERT INTO core.organizacion_sistema VALUES (2, 1);


--
-- TOC entry 3520 (class 0 OID 23475)
-- Dependencies: 264
-- Data for Name: permiso; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.permiso VALUES (1, 'Ver Usuarios', 'Puede visualizar usuarios', 'USR_VIEW', true);
INSERT INTO core.permiso VALUES (2, 'Crear Usuarios', 'Puede crear nuevos usuarios', 'USR_CREATE', true);
INSERT INTO core.permiso VALUES (3, 'Editar Usuarios', 'Puede modificar usuarios existentes', 'USR_EDIT', true);
INSERT INTO core.permiso VALUES (5, 'Ver Contactos', 'Puede visualizar contactos', 'CNT_VIEW', true);
INSERT INTO core.permiso VALUES (6, 'Crear Contactos', 'Puede crear nuevos contactos', 'CNT_CREATE', true);
INSERT INTO core.permiso VALUES (7, 'Editar Contactos', 'Puede modificar contactos', 'CNT_EDIT', true);
INSERT INTO core.permiso VALUES (8, 'Eliminar Contactos', 'Puede eliminar contactos', 'CNT_DELETE', false);
INSERT INTO core.permiso VALUES (9, 'Ver Organizaciones', 'Puede visualizar organizaciones', 'ORG_VIEW', true);
INSERT INTO core.permiso VALUES (12, 'Crear Bodegas', 'Puede Crear nuevas bodegas', 'BDG_CREATE', true);
INSERT INTO core.permiso VALUES (13, 'Editar Bodegas', 'Puede Editar informacion de bodegas', 'BDG_EDIT', true);
INSERT INTO core.permiso VALUES (14, 'Eliminar Bodegas', 'Puede Eliminar bodegas', 'BDG_DELETE', true);
INSERT INTO core.permiso VALUES (10, 'Administrar Sistema', 'Puede administrar configuraciones del sistema', 'SYS_ADMIN', true);
INSERT INTO core.permiso VALUES (11, 'Ver Bodegas', 'Puede Listar bodegas', 'BDG_VIEW', true);
INSERT INTO core.permiso VALUES (4, 'Eliminar Usuarios', 'Puede eliminar usuarios', 'USR_DELETE', false);
INSERT INTO core.permiso VALUES (15, 'Crear Item', 'Puede Crear Item', 'ITM_CREATE', true);
INSERT INTO core.permiso VALUES (16, 'Ver Iitem', 'Puede visualizar Item', 'ITM_VIEW', true);
INSERT INTO core.permiso VALUES (17, 'Editar Item', 'Puede modificar item existentes', 'ITM_EDIT', true);
INSERT INTO core.permiso VALUES (18, 'Eliminar item', 'Puede eliminar item', 'ITM_DELETE', true);
INSERT INTO core.permiso VALUES (19, 'Leer Menu', 'Puede ver menu de shell', 'MENU_VIEW', true);


--
-- TOC entry 3518 (class 0 OID 23465)
-- Dependencies: 262
-- Data for Name: rol; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.rol VALUES (1, 'Super Administrador', 'Acceso completo a todo el sistema', 'SUPER_ADMIN');
INSERT INTO core.rol VALUES (2, 'Administrador', 'Acceso administrativo limitado', 'ADMIN');
INSERT INTO core.rol VALUES (3, 'Usuario Estándar', 'Acceso básico de usuario', 'USR_STD');
INSERT INTO core.rol VALUES (4, 'Supervisor', 'Supervisión de operaciones', 'SUPERVISOR');
INSERT INTO core.rol VALUES (5, 'Solo Lectura', 'Solo puede consultar información', 'READ_ONLY');


--
-- TOC entry 3522 (class 0 OID 23489)
-- Dependencies: 266
-- Data for Name: rol_modulo_permiso; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.rol_modulo_permiso VALUES (1, 1, 1);
INSERT INTO core.rol_modulo_permiso VALUES (1, 1, 2);
INSERT INTO core.rol_modulo_permiso VALUES (1, 1, 3);
INSERT INTO core.rol_modulo_permiso VALUES (1, 1, 4);
INSERT INTO core.rol_modulo_permiso VALUES (1, 1, 10);
INSERT INTO core.rol_modulo_permiso VALUES (1, 2, 5);
INSERT INTO core.rol_modulo_permiso VALUES (1, 2, 6);
INSERT INTO core.rol_modulo_permiso VALUES (1, 2, 7);
INSERT INTO core.rol_modulo_permiso VALUES (1, 2, 8);
INSERT INTO core.rol_modulo_permiso VALUES (1, 3, 9);
INSERT INTO core.rol_modulo_permiso VALUES (2, 1, 1);
INSERT INTO core.rol_modulo_permiso VALUES (2, 1, 2);
INSERT INTO core.rol_modulo_permiso VALUES (2, 1, 3);
INSERT INTO core.rol_modulo_permiso VALUES (2, 2, 5);
INSERT INTO core.rol_modulo_permiso VALUES (2, 2, 6);
INSERT INTO core.rol_modulo_permiso VALUES (2, 2, 7);
INSERT INTO core.rol_modulo_permiso VALUES (2, 3, 9);
INSERT INTO core.rol_modulo_permiso VALUES (3, 1, 1);
INSERT INTO core.rol_modulo_permiso VALUES (3, 2, 5);
INSERT INTO core.rol_modulo_permiso VALUES (3, 3, 9);
INSERT INTO core.rol_modulo_permiso VALUES (5, 1, 1);
INSERT INTO core.rol_modulo_permiso VALUES (5, 2, 5);
INSERT INTO core.rol_modulo_permiso VALUES (5, 3, 9);
INSERT INTO core.rol_modulo_permiso VALUES (4, 6, 11);
INSERT INTO core.rol_modulo_permiso VALUES (4, 6, 12);
INSERT INTO core.rol_modulo_permiso VALUES (4, 6, 13);
INSERT INTO core.rol_modulo_permiso VALUES (4, 6, 14);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 11);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 12);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 13);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 14);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 15);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 16);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 17);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 18);
INSERT INTO core.rol_modulo_permiso VALUES (1, 6, 19);


--
-- TOC entry 3513 (class 0 OID 23440)
-- Dependencies: 257
-- Data for Name: sistema; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.sistema VALUES (1, 'ERP Core', 'Sistema de gestión empresarial principal', true);
INSERT INTO core.sistema VALUES (2, 'CRM', 'Sistema de gestión de clientes', true);
INSERT INTO core.sistema VALUES (3, 'Inventario', 'Sistema de gestión de inventario', false);


--
-- TOC entry 3505 (class 0 OID 23403)
-- Dependencies: 249
-- Data for Name: tipo_contacto; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.tipo_contacto VALUES (1, 'Persona', 'Contacto personal');
INSERT INTO core.tipo_contacto VALUES (2, 'Empresa', 'Contacto empresarial');
INSERT INTO core.tipo_contacto VALUES (3, 'Proveedor', 'Contacto de proveedor');
INSERT INTO core.tipo_contacto VALUES (4, 'Cliente', 'Contacto de cliente');


--
-- TOC entry 3524 (class 0 OID 23496)
-- Dependencies: 268
-- Data for Name: usuario; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.usuario VALUES (1, 'admin', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '2025-09-24', true, NULL, 1);
INSERT INTO core.usuario VALUES (2, 'maria.admin', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '2025-09-24', true, NULL, 2);
INSERT INTO core.usuario VALUES (3, 'usuario.test', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '2025-09-24', true, NULL, 3);
INSERT INTO core.usuario VALUES (4, 'sparra', '$2a$12$bSTrdJgKk9E6mEJYyLGe9O.YB5QXHCumMhE/66Ceky8J2mwnM4lnq', '2025-09-24', true, NULL, 4);


--
-- TOC entry 3525 (class 0 OID 23505)
-- Dependencies: 269
-- Data for Name: usuario_rol; Type: TABLE DATA; Schema: core; Owner: desarrollo
--

INSERT INTO core.usuario_rol VALUES (1, 1);
INSERT INTO core.usuario_rol VALUES (2, 2);
INSERT INTO core.usuario_rol VALUES (3, 3);
INSERT INTO core.usuario_rol VALUES (4, 1);
