# SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
# SPDX-License-Identifier: MIT

GET {{conch}}
HTTP 200

GET {{conch}}/sign
HTTP 500

GET {{conch}}/sign
Authorization: Bearer {{ token }}
HTTP 200
