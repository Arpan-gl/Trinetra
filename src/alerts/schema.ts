/**
 * PassiveSentinel - Alert Schema Validator
 * Validates alert records strictly against schema/alert.schema.json using Ajv.
 */

import Ajv from "ajv";
import addFormats from "ajv-formats";
import * as path from "path";
import * as fs from "fs";
import { AlertRecord } from "../engine/protocol";

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

const schemaPath = path.resolve(__dirname, "../../schema/alert.schema.json");
const schemaJson = JSON.parse(fs.readFileSync(schemaPath, "utf-8"));
const validateFn = ajv.compile(schemaJson);

export function validateAlert(alert: any): { valid: boolean; errors: string[] } {
  const valid = validateFn(alert);
  if (!valid && validateFn.errors) {
    const errorMsgs = validateFn.errors.map(
      (e) => `${e.instancePath || "/"} ${e.message}`
    );
    return { valid: false, errors: errorMsgs };
  }
  return { valid: true, errors: [] };
}
