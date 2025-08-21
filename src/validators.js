// src/validators.js
const { body } = require('express-validator');

exports.login = [
  body('email').isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password required (min 6 chars)')
];

exports.registerEmployee = [
  body('name').notEmpty().withMessage('Name required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password min 6 chars'),
  body('phone').optional().isString(),
  body('work_status').optional().isString()
];

exports.registerEmployer = [
  body('name').notEmpty().withMessage('Name required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password min 6 chars'),
  body('company_name').notEmpty().withMessage('Company name required'),
  body('website').optional().isURL().withMessage('Website must be URL').optional({ nullable: true }),
  body('gst_number').optional().isString()
];

exports.registerRecruiter = [
  body('name').notEmpty().withMessage('Name required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password min 6 chars'),
  body('agency_name').optional().isString(),
  body('specialization').optional().isString(),
  body('years_experience').optional().isInt({ min: 0 })
];
