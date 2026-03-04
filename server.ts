/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import i18n from 'i18n'
import cors from 'cors'
import fs from 'node:fs'
import yaml from 'js-yaml'
import config from 'config'
import morgan from 'morgan'
import multer from 'multer'
import helmet from 'helmet'
import http from 'node:http'
import path from 'node:path'
import express from 'express'
import colors from 'colors/safe'
import bodyParser from 'body-parser'
// @ts-expect-error FIXME due to non-existing type definitions for finale-rest
import * as finale from 'finale-rest'
import compression from 'compression'
// @ts-expect-error FIXME due to non-existing type definitions for express-robots-txt
import robots from 'express-robots-txt'
import cookieParser from 'cookie-parser'
import * as Prometheus from 'prom-client'
import swaggerUi from 'swagger-ui-express'
import featurePolicy from 'feature-policy'
import { IpFilter } from 'express-ipfilter'
// @ts-expect-error FIXME due to non-existing type definitions for express-security.txt
import securityTxt from 'express-security.txt'