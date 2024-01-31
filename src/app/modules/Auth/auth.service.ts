import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import { User } from '../User/user.model';
import { TLoginUser } from './auth.interface';
import { bcryptHelper } from '../../utils/bycryptHelper';
import { jwtHelper } from '../../utils/jwtHelpers';
import config from '../../config';

const loginUser = async (payload: TLoginUser) => {
  // checking if the user is exist
  const user = await User.findOne({
    email: payload.email,
  });

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
  }

  const isPasswordMatched = await bcryptHelper.isPasswordMatched(
    payload?.password,
    user?.password,
  );
  if (!isPasswordMatched) {
    throw new AppError(httpStatus.FORBIDDEN, 'Password do not matched');
  }

  //create token and sent to the  client

  const jwtPayload = {
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtHelper.createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string,
  );

  const refreshToken = jwtHelper.createToken(
    jwtPayload,
    config.jwt_refresh_secret as string,
    config.jwt_refresh_expires_in as string,
  );

  return {
    accessToken,
    refreshToken,
  };
};

const refreshToken = async (token: string) => {
  // checking if the given token is valid
  const decoded = jwtHelper.verifyToken(
    token,
    config.jwt_refresh_secret as string,
  );

  if (typeof decoded === 'string' || !decoded || decoded instanceof Error) {
    throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized !');
  }

  const { email } = decoded;

  // checking if the user is exist
  const user = await User.findOne({
    email,
  });

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
  }

  const jwtPayload = {
    userId: user.id,
    role: user.role,
  };

  const accessToken = jwtHelper.createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string,
  );

  return {
    accessToken,
  };
};

export const AuthServices = {
  loginUser,
  refreshToken,
};
