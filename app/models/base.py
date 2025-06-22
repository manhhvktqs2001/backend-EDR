# app/models/base.py - Base import fix
"""
Base model for all database models
"""

from sqlalchemy.ext.declarative import declarative_base

# Create base model
Base = declarative_base()

# Make it available for import
__all__ = ['Base']