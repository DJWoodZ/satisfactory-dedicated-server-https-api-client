const StatusCode = require('../../src/enums/StatusCode');

describe('StatusCode Enumeration', () => {
  it('should be an object with frozen properties', () => {
    expect(typeof StatusCode === 'object').toBeTruthy();
    expect(Object.prototype.isPrototypeOf.call(Object.getPrototypeOf(StatusCode), Object))
      .toBeTruthy();
    expect(Object.isFrozen(StatusCode)).toBeTruthy();
  });

  it('should have the correct property keys', () => {
    const expectedKeys = [
      'OK',
      'CREATED',
      'ACCEPTED',
      'NO_CONTENT',
      'BAD_REQUEST',
      'DENIED',
      'FORBIDDEN',
      'NOT_FOUND',
      'UNSUPPORTED_MEDIA',
      'SERVER_ERROR',
    ];
    expect(Object.keys(StatusCode)).toEqual(expectedKeys);
  });

  it('should have valid status code values', () => {
    const expectedValues = [
      { code: 200, name: 'Ok' },
      { code: 201, name: 'Created' },
      { code: 202, name: 'Accepted' },
      { code: 204, name: 'No Content' },
      { code: 400, name: 'Bad Request' },
      { code: 401, name: 'Denied' },
      { code: 403, name: 'Forbidden' },
      { code: 404, name: 'Not Found' },
      { code: 415, name: 'Unsupported Media' },
      { code: 500, name: 'Server Error' },
    ];
    expect(Object.values(StatusCode)).toEqual(expectedValues);
  });

  it('should throw an error when accessing an invalid property', () => {
    const unknownProperty = 'Unknown';
    expect(() => StatusCode[unknownProperty]).toThrow(Error);
    expect(() => StatusCode[unknownProperty]).toThrow(`'${unknownProperty}' is not a valid status code`);
  });

  it('should be case-sensitive when accessing property values', () => {
    const lowerCaseProp = 'ok';
    expect(() => StatusCode[lowerCaseProp]).toThrow(Error);
  });
});

describe('getStatusByCode method', () => {
  it('returns the correct status for a given code', () => {
    expect(StatusCode.getStatusByCode(200)).toEqual({
      name: 'Ok',
      code: 200,
    });
  });

  it('throws error for an invalid code', () => {
    const unknownCode = 9999;
    expect(() => StatusCode.getStatusByCode(unknownCode)).toThrow(Error);
    expect(() => StatusCode.getStatusByCode(unknownCode)).toThrow(`'${unknownCode}' is not a valid status code`);
  });
});

describe('getStatusByName method', () => {
  it('returns the correct status for a given name', () => {
    expect(StatusCode.getStatusByName('Ok')).toEqual({
      name: 'Ok',
      code: 200,
    });

    expect(StatusCode.getStatusByName('ok')).toEqual({
      name: 'Ok',
      code: 200,
    });

    expect(StatusCode.getStatusByName('OK')).toEqual({
      name: 'Ok',
      code: 200,
    });
  });

  it('throws error for an invalid name', () => {
    const unknownName = 'Unknown';
    expect(() => StatusCode.getStatusByName(unknownName)).toThrow(Error);
    expect(() => StatusCode.getStatusByName(unknownName)).toThrow(`'${unknownName}' is not a valid status name`);
  });
});

describe('getSuccessfulStatusCodes method', () => {
  it('returns an array of all successful status codes', () => {
    expect(StatusCode.getSuccessfulStatusCodes()).toEqual([200, 201, 202, 204]);
  });
});

describe('getErrorCodes method', () => {
  it('returns an array of all error codes', () => {
    expect(StatusCode.getErrorCodes()).toEqual([400, 401, 403, 404, 415, 500]);
  });
});
