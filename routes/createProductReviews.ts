/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import { reviewsCollection } from '../data/mongodb'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

/* module.exports = function productReviews () {
  return (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user && user.data.email !== req.body.author })
    reviewsCollection.insert({
      product: req.params.id,
      message: req.body.message,
      author: req.body.author,
      likesCount: 0,
      likedBy: []
    }).then(() => {
      res.status(201).json({ status: 'success' })
    }, (err: unknown) => {
      res.status(500).json(utils.getErrorMessage(err))
    })
  }
}
*/
module.exports = function productReviews() {
  return (req: Request, res: Response) => {
    // Validación de la entrada de 'message' y 'author'
    const { message, author } = req.body;

    // Verificar que 'message' no esté vacío y sea una cadena
    if (typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message must be a non-empty string' });
    }

    // Verificar que 'author' sea un correo electrónico válido
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (typeof author !== 'string' || !emailRegex.test(author)) {
      return res.status(400).json({ error: 'Author must be a valid email' });
    }

    // Obtener el usuario autenticado
    const user = security.authenticatedUsers.from(req);

    // Verificar si el reto de revisión falsificada debe resolverse
    challengeUtils.solveIf(challenges.forgedReviewChallenge, () => {
      return user && user.data.email !== req.body.author;
    });

    // Prevenir la inyección directa al insertar de forma segura
    const review = {
      product: req.params.id,
      message: message,
      author: author,
      likesCount: 0,
      likedBy: []
    };

    // Insertar de forma segura en la base de datos
    reviewsCollection.insert(review).then(() => {
      res.status(201).json({ status: 'success' });
    }, (err: unknown) => {
      res.status(500).json(utils.getErrorMessage(err));
    });
  };
};
