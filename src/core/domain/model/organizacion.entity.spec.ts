/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { OrganizacionEntity } from 'src/infrastructure/database/entities/organizacion.entity';

describe('OrganizacionEntity', () => {
    let organizacionEntity: OrganizacionEntity;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        organizacionEntity = moduleRef.get<OrganizacionEntity>(OrganizacionEntity);
    });

    it('should be defined', () => {
        expect(organizacionEntity).toBeDefined();
    });
});
