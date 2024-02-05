import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import { bcryptHelper } from '../../utils/bycryptHelper';
import { User } from '../User/user.model';
import { TLoginUser } from './auth.interface';

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
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars
  const { password, ...restUserInfo } = user.toJSON();

  return restUserInfo;
};

export const AuthServices = {
  loginUser,
};
